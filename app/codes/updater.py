"""Updater that adds a new block and updates state db"""
import datetime
import json
import os
import logging
import sqlite3
import threading
from app.codes.fs.temp_manager import store_receipt_to_temp
from app.codes.p2p.sync_chain import sync_chain_from_peers
from app.codes.timers import SYNC_STATUS

# from app.codes.receiptmanager import get_receipts_for_block_from_db
from app.ntypes import BLOCK_VOTE_MINER

from .clock.global_time import get_corrected_time_ms, get_time_difference
from .fs.temp_manager import get_all_receipts_from_storage, get_blocks_for_index_from_storage, store_block_to_temp
from .minermanager import am_i_in_current_committee, broadcast_miner_update, get_committee_for_current_block, get_miner_for_current_block, should_i_mine
from ..Configuration import Configuration
from ..nvalues import SENTINEL_NODE_WALLET, TREASURY_WALLET_ADDRESS
from ..constants import ALLOWED_FEE_PAYMENT_TOKENS, BLOCK_RECEIVE_TIMEOUT_SECONDS, BLOCK_TIME_INTERVAL_SECONDS, COMMITTEE_SIZE, GLOBAL_INTERNAL_CLOCK_SECONDS, IS_TEST, MINIMUM_ACCEPTANCE_VOTES, NEWRL_DB, NEWRL_PORT, NO_BLOCK_TIMEOUT, NO_RECEIPT_COMMITTEE_TIMEOUT, REQUEST_TIMEOUT, MEMPOOL_PATH, SOFTWARE_VERSION, TIME_BETWEEN_BLOCKS_SECONDS, TIME_MINER_BROADCAST_INTERVAL_SECONDS
from .p2p.peers import get_peers
from .p2p.utils import is_my_address
from .utils import BufferedLog, get_time_ms
from .blockchain import Blockchain, get_last_block, get_last_block_index
from .transactionmanager import Transactionmanager, get_valid_addresses
from .state_updater import pay_fee_for_transaction, update_db_states
from .crypto import calculate_hash, sign_object, _private, _public
from .consensus.consensus import generate_block_receipt
from .db_updater import transfer_tokens_and_update_balances, get_wallet_token_balance
from .p2p.outgoing import broadcast_block, broadcast_receipt, send_request_in_thread
from .auth.auth import get_wallet
from .timers import TIMERS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


MAX_BLOCK_SIZE = 1000


def run_updater(add_to_chain=False):
    # logger = BufferedLog()
    blockchain = Blockchain()

    con = sqlite3.connect(NEWRL_DB)
    cur = con.cursor()
    block_time_limit = 1  # Number of hours of no transactions still prompting new block
    block_height = 0
    latest_ts = blockchain.get_latest_ts(cur)
    previous_block = get_last_block(cur=cur)
    if previous_block is None:
        new_block_index = 1
    else:
        new_block_index = previous_block['index'] + 1

    existing_block_proposals = get_blocks_for_index_from_storage(new_block_index)
    if len(existing_block_proposals) != 0:
        logger.info(f"Existing block proposal exists with index {new_block_index}. Broadcasting existing one.")
        broadcast_block_proposal(existing_block_proposals[0])
        return existing_block_proposals[0]

    logger.info(f'Proposing new block {new_block_index}')
    filenames = os.listdir(MEMPOOL_PATH)  # this is the mempool
    logger.info(f"Files in mempool: {filenames}")
    textarray = []
    transfiles = filenames
    txcodes = []
    tmtemp = Transactionmanager()

    transaction_fees = 0

    for filename in transfiles:
        file = MEMPOOL_PATH + filename
        try:
            with open(file, "r") as read_file:
                logger.info(f"Processing {file}")
                transaction_file_data = json.load(read_file)
        except:
            logger.info(f"Couldn't load transaction file {file}")
            continue
        
        transaction = transaction_file_data['transaction']
        signatures = transaction_file_data['signatures']

        # new code for validating again
        trandata = tmtemp.loadtransactionpassive(file)
        if not tmtemp.verifytransigns():
            logger.info(
                f"Transaction id {trandata['transaction']['trans_code']} has invalid signatures")
            os.remove(file)
            continue
        # Pay fee for transaction. If payee doesn't have enough funds, remove transaction
        if not pay_fee_for_transaction(cur, transaction):
            os.remove(file)
            continue
        if not tmtemp.econvalidator():
            logger.info(f"Economic validation failed for transaction {trandata['transaction']['trans_code']}")
            os.remove(file)
            continue

        logger.info("Found valid transaction, checking if it is already included")
        transactions_cursor = cur.execute("SELECT * FROM transactions where transaction_code='" + transaction['trans_code'] + "'")
        row = transactions_cursor.fetchone()
        if row is not None:
            # The current transaction is already included in some earlier block
            os.remove(file)
            continue
        
        if not should_include_transaction(transaction, new_block_index - 1):
            os.remove(file)
            continue
        
        if trandata['transaction']['trans_code'] not in txcodes:
            textarray.append(transaction_file_data)
            txcodes.append(trandata['transaction']['trans_code'])

            # transaction_fees += get_fees_for_transaction(trandata['transaction'])
            # Delete the transaction from mempool at the stage of accepting
            # try:
            #     os.remove(file)
            # except:
            #     logger.info("Couldn't delete:",file)
        block_height += 1
        if block_height >= MAX_BLOCK_SIZE:
            logger.info(
                "Reached max block height, moving forward with the collected transactions")
            break

    transactionsdata = {"transactions": textarray}
    if len(textarray) > 0:
        logger.info(f"Found {len(textarray)} transactions. Adding to chain")
    else:
        logger.info("No new transactions. Checking for time.")
        logger.info(f"latest TS:{latest_ts} Now: {datetime.datetime.now()}")
        try:
            time_diff = get_time_ms() - int(latest_ts)
        except Exception as e:
            time_diff = TIME_BETWEEN_BLOCKS_SECONDS * 1000 + 1  # Set a high timelimit as no last block timestamp found
        logger.info(f"Time since last block: {time_diff} seconds")
        if time_diff < TIME_BETWEEN_BLOCKS_SECONDS * 1000:  # TODO - Change the block time limit
            logger.info("No new transactions, not enough time since last block. Exiting.")
            return None
        else:
            logger.info(f"More than {TIME_BETWEEN_BLOCKS_SECONDS} seconds since the last block. Adding a new empty one.")

    # transactionsdata['previous_block_receipts'] = get_receipts_from_storage(previous_block['index'])
    if previous_block is not None:
        transactionsdata['previous_block_receipts'] = get_all_receipts_from_storage(exclude_block_index=previous_block['index'] + 1)
        receipts_to_include_count = MAX_BLOCK_SIZE - len(textarray)
        transactionsdata['previous_block_receipts'] = transactionsdata['previous_block_receipts'][:receipts_to_include_count]
    else:
        transactionsdata['previous_block_receipts'] = []
    # transactionsdata['previous_block_proposals'] = get_proposals_for_block(previous_block['index'])

    if add_to_chain:
        block = blockchain.mine_block(cur, transactionsdata)
        update_db_states(cur, block)
        con.commit()
        con.close()
    else:
        block = blockchain.propose_block(cur, transactionsdata)
    block_receipt = generate_block_receipt(block, vote=BLOCK_VOTE_MINER)
    block_payload = {
        'index': block['index'],
        'hash': calculate_hash(block),
        'data': block,
        'receipts': [block_receipt],
        'software_version': SOFTWARE_VERSION
    }
    store_block_to_temp(block_payload)
    # store_receipt_to_temp(block_receipt)
    logger.info(f'Stored block to temp with payload {json.dumps(block_payload)}')
    broadcast_block_proposal(block_payload, block_receipt)

    return block_payload


def broadcast_block_proposal(block_payload, block_receipt=None):
    if not IS_TEST:
        nodes = get_committee_for_current_block()
        if len(nodes) < MINIMUM_ACCEPTANCE_VOTES:
            peers = get_peers()
            if len(peers) > len(nodes):
                logger.info('Committee not adequate. Broadcasting block proposal to all peers.')
                nodes = peers
        broadcast_block(block_payload, nodes)
        if block_receipt is not None:
            broadcast_receipt(block_receipt, nodes)


def create_empty_block_receipt_and_broadcast():
    logger.info('No block timeout. Mining empty block and sending receipts.')
    # block_index = get_last_block_index() + 1
    # blocks_in_storage = get_blocks_for_index_from_storage(block_index)
    # if len(blocks_in_storage) != 0:
    #     logger.info('Block already exist in storage. Not mining empty block.')
    #     return
    blockchain = Blockchain()
    block = blockchain.mine_empty_block()
    block_receipt = generate_block_receipt(block)
    block_payload = {
        'index': block['index'],
        'hash': calculate_hash(block),
        'data': block,
        'receipts': [block_receipt]
    }
    store_block_to_temp(block_payload)

    committee = get_committee_for_current_block()
    broadcast_receipt(block_receipt, committee)
    return block_payload


def start_empty_block_mining_clock(block_timestamp):
    global TIMERS
    current_ts_seconds = get_corrected_time_ms() / 1000
    block_ts_seconds = block_timestamp / 1000
    seconds_to_wait = block_ts_seconds + BLOCK_TIME_INTERVAL_SECONDS + NO_BLOCK_TIMEOUT - current_ts_seconds
    timer = threading.Timer(seconds_to_wait, create_empty_block_receipt_and_broadcast)
    timer.start()
    TIMERS['block_receive_timeout'] = timer


def mine(add_to_chain=False):
    if should_i_mine() or add_to_chain:
        logger.info('I am the miner for this block.')
        return run_updater(add_to_chain)
    # elif am_i_in_current_committee():
    #     start_empty_block_mining_clock()
    #     logger.info('I am committee member. Starting no block timeout.')
    else:
        miner = get_miner_for_current_block()
        logger.info(f"Miner for current block is {miner['wallet_address']}. Waiting to receive block.")


def start_mining_clock(block_timestamp):    
    # if TIMERS['mining_timer'] is not None:
    #     TIMERS['mining_timer'].cancel()
    # if TIMERS['block_receive_timeout'] is not None:
    #     TIMERS['block_receive_timeout'].cancel()
    #     TIMERS['block_receive_timeout'] = None
    current_ts_seconds = get_corrected_time_ms() / 1000
    block_ts_seconds = block_timestamp / 1000
    seconds_to_wait = block_ts_seconds + BLOCK_TIME_INTERVAL_SECONDS - current_ts_seconds
    logger.info(f'Block time timestamp is {block_ts_seconds}. Current timestamp is {current_ts_seconds}. Waiting {seconds_to_wait} seconds to mine next block')
    timer = threading.Timer(seconds_to_wait, mine)
    timer.start()
    TIMERS['mining_timer'] = timer


def start_miner_broadcast_clock():
    logger.info('Broadcasting miner update')
    try:
        broadcast_miner_update()
    except Exception as e:
        logger.info(f'Could not broadcast miner update {e}')
    timer = threading.Timer(TIME_MINER_BROADCAST_INTERVAL_SECONDS, start_miner_broadcast_clock)
    timer.start()


def should_include_transaction(transaction, my_last_block_index=0):
    try:
        if transaction['type'] == 7:
            broadcast_timestamp = transaction['specific_data']['broadcast_timestamp']
            if broadcast_timestamp < get_corrected_time_ms() - TIME_MINER_BROADCAST_INTERVAL_SECONDS * 1000:
                return False
            software_version = transaction['specific_data']['software_version']
            last_block_index = transaction['specific_data']['last_block_index']
            if software_version < SOFTWARE_VERSION or last_block_index < my_last_block_index:
                return False
    except Exception as e:
        logger.error(f'Invalid transaction format {str(transaction)}, {str(e)}')
        return False
    return True


def global_internal_clock():
    """Reccuring clock for all node level activities"""
    global TIMERS
    global SYNC_STATUS

    if SYNC_STATUS['IS_SYNCING']:
        logger.info('Timer tick. Syncing with network. Continuing sync.')
    else:
        try:
            # Check for mining delay
            current_ts = get_corrected_time_ms()
            last_block = get_last_block()
            if last_block:
                last_block_ts = int(last_block['timestamp'])
                time_elapsed_seconds = (current_ts - last_block_ts) / 1000

                if time_elapsed_seconds > BLOCK_TIME_INTERVAL_SECONDS * 4:
                    logger.info('I have not received a block for 4 intervals. Querying chain for majority chain.')
                    sync_chain_from_peers()
                if should_i_mine(last_block):
                    if TIMERS['mining_timer'] is None or not TIMERS['mining_timer'].is_alive():
                        start_mining_clock(last_block_ts)
                elif time_elapsed_seconds > BLOCK_TIME_INTERVAL_SECONDS * 8:
                    if am_i_sentinel_node():
                        logger.info('I am sentitnel node. Mining empty block')
                        sentitnel_node_mine_empty()

                # elif am_i_in_current_committee(last_block):
                #     if TIMERS['block_receive_timeout'] is None or not TIMERS['block_receive_timeout'].is_alive():
                #         start_empty_block_mining_clock(last_block_ts)
            else:
                logger.info('No blocks with me. Syncing with the network.')
                sync_chain_from_peers()
        except Exception as e:
            logger.info(f'Error in global clock {e}')

    timer = threading.Timer(GLOBAL_INTERNAL_CLOCK_SECONDS, global_internal_clock)
    timer.start()


def am_i_sentinel_node():
    my_wallet = get_wallet()
    return my_wallet['address'] == Configuration.config("SENTINEL_NODE_WALLET")


def sentitnel_node_mine_empty():
    previous_block = get_last_block()
    if previous_block is None:
        new_block_index = 1
    else:
        new_block_index = previous_block['index'] + 1
    existing_block_proposals = get_blocks_for_index_from_storage(new_block_index)
    
    if len(existing_block_proposals) != 0:
        logger.info(f"Existing block proposal exists with index {new_block_index}. Broadcasting existing one.")
        broadcast_block_proposal(existing_block_proposals[0])
        return existing_block_proposals[0]
    blockchain = Blockchain()
    current_time_ms = get_corrected_time_ms()
    block = blockchain.mine_empty_block(current_time_ms)
    block_receipt = generate_block_receipt(block)
    block_payload = {
        'index': block['index'],
        'hash': calculate_hash(block),
        'data': block,
        'receipts': [block_receipt]
    }
    broadcast_block(block_payload=block_payload)


def get_timers():
    """Get timer status"""
    return {
        'is_mining': TIMERS['mining_timer'] is not None and TIMERS['mining_timer'].is_alive(),
        'is_waiting_block_timeout': TIMERS['block_receive_timeout'] is not None and TIMERS['block_receive_timeout'].is_alive(),
    }