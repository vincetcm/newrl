import os

from app.ntypes import NEWRL_TOKEN_DECIMAL


NEWRL_ENV = os.environ.get('NEWRL_ENV')

if NEWRL_ENV == 'testnet':
    ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
    TREASURY_WALLET_ADDRESS = '0x1111111111111111111111111111111111111111'
    NETWORK_TRUST_MANAGER_WALLET = '0x1111111111111111111111111111111111111112'
    NETWORK_TRUST_MANAGER_PID = 'pi1111111111111111111111111111111111111112'
    ASQI_PID = 'pi1111111111111111111111111111111111111114'
    ASQI_WALLET = '0xce4b9b89efa5ee6c34655c8198c09494dc3d95bb'
    ASQI_WALLET_PUBLIC = 'f9a8e9773c706a6c32182144dd656409853b7eb25782ba61e5b9030ae19baf63fea3672464496e8ac4ac7046bedcbe7ae9f1d20481fcbceefc22afdfbf14ee27'
    ASQI_WALLET_DAO = ASQI_WALLET
    FOUNDATION_WALLET = '0xce6124c19691a2f140f141705ce1791d45c347a5'
    FOUNDATION_WALLET_PUBLIC = '5836e0dfd772050c5cb807f36dfe5a65ff2234ad0723e52c42e1d6fddb0aca7d68718a500ef63caa4641044d73b6b7ecc05091bb2ca2cd7b7061164a262b5d95'
    FOUNDATION_WALLET_DAO = FOUNDATION_WALLET
    SENTINEL_NODE_WALLET = '0xd6c038f5c25dae8a8f7350a58fb79ef0c3c625a5'
    SENTINEL_NODE_WALLET_PUBLIC = 'fb4d35cb763fdc415323280155ffc14eabb40fd473f833b85aa6fd0aeb68eabea9a706bddf84267866af758d1c31596492154353ebc359150536606d44dc2368'
    DAO_MANAGER = 'ct9000000000000000000000000000000000000da0'
    NETWORK_TREASURY_ADDRESS = 'ct1111111111111111111111111111111111111112'
    FOUNDATION_TREASURY_ADDRESS = 'ct1111111111111111111111111111111111111113'
    ASQI_TREASURY_ADDRESS = 'ct1111111111111111111111111111111111111114'
    ASQI_DAO_ADDRESS = 'ctda01111111111111111111111111111111111114'
    CUSTODIAN_DAO_ADDRESS = 'ctda01111111111111111111111111111111111da0'
    FOUNDATION_DAO_ADDRESS = 'ctda01111111111111111111111111111111111113'
    CONFIG_DAO_ADDRESS = 'ct1111111111111111111111111111111111111111'
    STAKE_COOLDOWN_MS = 600000
    MIN_STAKE_AMOUNT = 500000 * pow(10, NEWRL_TOKEN_DECIMAL)
    STAKE_PENALTY_RATIO = 10
    STAKE_CT_ADDRESS = 'ct1111111111111111111111111111111111111115'
    MEMBER_WALLET_LIST = [
        '0xf98eafede44ae6db2f6e6ad3762f5419ff1196d9',
        '0x9dd356a2e4aa9a6c182d5f1e3f2e40ffa27bcfd5',
        '0x47538e46a78e729079eb1614e2d6c387119c21fa',
        '0x1342e0ae1664734cbbe522030c7399d6003a07a8',
        '0x495c8153f65cf402bb0af6f93ba1eed4ace9aa7f',
        '0x52c3a0758644133fbbf85377244a35d932443bf0',
        '0x5017b00ced00b8b51d77d4569fa9d611b5b3b77a'
    ]
    CUSTODIAN_WALLET_LIST = MEMBER_WALLET_LIST + [
        'ct9000000000000000000000000000000000000da0',
        CUSTODIAN_DAO_ADDRESS,
        ASQI_WALLET,
        FOUNDATION_WALLET,
    ]
elif NEWRL_ENV == 'mainnet':
    ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
    TREASURY_WALLET_ADDRESS = '0x1111111111111111111111111111111111111111'
    NETWORK_TRUST_MANAGER_WALLET = '0x1111111111111111111111111111111111111112'
    NETWORK_TRUST_MANAGER_PID = 'pi1111111111111111111111111111111111111112'
    ASQI_PID = 'pi1111111111111111111111111111111111111114'
    ASQI_WALLET = '0xce4b9b89efa5ee6c34655c8198c09494dc3d95bb'  #TODO -change SP keep
    ASQI_WALLET_PUBLIC = 'f9a8e9773c706a6c32182144dd656409853b7eb25782ba61e5b9030ae19baf63fea3672464496e8ac4ac7046bedcbe7ae9f1d20481fcbceefc22afdfbf14ee27'
    ASQI_WALLET_DAO = ASQI_WALLET
    FOUNDATION_WALLET = '0xce6124c19691a2f140f141705ce1791d45c347a5'    #TODO -change KR keep
    FOUNDATION_WALLET_PUBLIC = '5836e0dfd772050c5cb807f36dfe5a65ff2234ad0723e52c42e1d6fddb0aca7d68718a500ef63caa4641044d73b6b7ecc05091bb2ca2cd7b7061164a262b5d95'
    FOUNDATION_WALLET_DAO = FOUNDATION_WALLET
    SENTINEL_NODE_WALLET = '0xd6c038f5c25dae8a8f7350a58fb79ef0c3c625a5'  #TODO - Change
    SENTINEL_NODE_WALLET_PUBLIC = 'fb4d35cb763fdc415323280155ffc14eabb40fd473f833b85aa6fd0aeb68eabea9a706bddf84267866af758d1c31596492154353ebc359150536606d44dc2368'
    DAO_MANAGER = 'ct9000000000000000000000000000000000000da0'
    NETWORK_TREASURY_ADDRESS = 'ct1111111111111111111111111111111111111112'
    FOUNDATION_TREASURY_ADDRESS = 'ct1111111111111111111111111111111111111113'
    ASQI_TREASURY_ADDRESS = 'ct1111111111111111111111111111111111111114'
    ASQI_DAO_ADDRESS = 'ctda01111111111111111111111111111111111114'
    CUSTODIAN_DAO_ADDRESS = 'ctda01111111111111111111111111111111111da0'
    FOUNDATION_DAO_ADDRESS = 'ctda01111111111111111111111111111111111113'
    CONFIG_DAO_ADDRESS = 'ct1111111111111111111111111111111111111111'
    STAKE_COOLDOWN_MS = 600000
    MIN_STAKE_AMOUNT = 500000 * pow(10, NEWRL_TOKEN_DECIMAL)
    STAKE_PENALTY_RATIO = 10
    STAKE_CT_ADDRESS = 'ct1111111111111111111111111111111111111115'
    MEMBER_WALLET_LIST = [
        '0xf98eafede44ae6db2f6e6ad3762f5419ff1196d9',
        '0x9dd356a2e4aa9a6c182d5f1e3f2e40ffa27bcfd5',
        '0x47538e46a78e729079eb1614e2d6c387119c21fa',
        '0x1342e0ae1664734cbbe522030c7399d6003a07a8',
        '0x495c8153f65cf402bb0af6f93ba1eed4ace9aa7f',
        '0x52c3a0758644133fbbf85377244a35d932443bf0',
        '0x5017b00ced00b8b51d77d4569fa9d611b5b3b77a'
    ]
    CUSTODIAN_WALLET_LIST = MEMBER_WALLET_LIST + [
        'ct9000000000000000000000000000000000000da0',
        CUSTODIAN_DAO_ADDRESS,
        ASQI_WALLET,
        FOUNDATION_WALLET,
    ]
else:
    ZERO_ADDRESS = '0x0000000000000000000000000000000000000000'
    TREASURY_WALLET_ADDRESS = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'
    NETWORK_TRUST_MANAGER_WALLET = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'
    NETWORK_TRUST_MANAGER_PID = 'pi10d84aa634ba8751804ca4e02134696a75ae3515'
    ASQI_PID = 'pi10d84aa634ba8751804ca4e02134696a75ae3515'
    ASQI_WALLET = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'  # TODO - Need to store contract address instead
    ASQI_WALLET_DAO = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'
    ASQI_WALLET_PUBLIC = '09c191748cc60b43839b273083cc565811c26f5ce54b17ed4b4a17c61e7ad6b880fc7ac3081b9c0cf28756ea21ce501789b59e8f9103f3668ccf2c86108628ee'
    FOUNDATION_WALLET = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'  # TODO - Need to store contract address instead
    FOUNDATION_WALLET_DAO = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'
    FOUNDATION_WALLET_PUBLIC = '09c191748cc60b43839b273083cc565811c26f5ce54b17ed4b4a17c61e7ad6b880fc7ac3081b9c0cf28756ea21ce501789b59e8f9103f3668ccf2c86108628ee'
    SENTINEL_NODE_WALLET = '0x667663f36ac08e78bbf259f1361f02dc7dad593b'
    SENTINEL_NODE_WALLET_PUBLIC = '09c191748cc60b43839b273083cc565811c26f5ce54b17ed4b4a17c61e7ad6b880fc7ac3081b9c0cf28756ea21ce501789b59e8f9103f3668ccf2c86108628ee'
    DAO_MANAGER = 'ct9dc895fe5905dc73a2273e70be077bf3e94ea3b7'
    NETWORK_TREASURY_ADDRESS = 'ctb020e608d11c235724e676d021a08f8da6c64eb8'
    ASQI_TREASURY_ADDRESS = 'ctb020e608d11c235724e676d021a08f8da6c64fb9'
    FOUNDATION_TREASURY_ADDRESS = 'ctb020e608d11c235724e676d021a08f8da6c64fc1'
    ASQI_DAO_ADDRESS = 'ctb020e608d11c235724e676d021a08f8da6c64eb9'
    FOUNDATION_DAO_ADDRESS = 'ctb020e608d11c235724e676d021a08f8da6c64ec1'
    CONFIG_DAO_ADDRESS = 'ctb020e608d11c235724e676d021a08f8da6c64ec2'
    STAKE_COOLDOWN_MS=600000
    MIN_STAKE_AMOUNT = 500000 * pow(10, NEWRL_TOKEN_DECIMAL)
    STAKE_PENALTY_RATIO=10
    STAKE_CT_ADDRESS='ctcdb91798f3022dee388b7ad55eeea527f98caee4'
    MEMBER_WALLET_LIST = [
        '0xdc5ce2dd2103635210591bd43cf1a95c9406c1b2',
        '0x8159aacfd3e3d9afbb9dff37bf1896e0479d19a6',
        '0x7633fb937d7970e1668a16999453bbb64a30fcf1',
        '0xd506831f17f6936e27bd1a9187efd48c23c0bcbb',
        '0xbc54ef523d92b6acaf16a49b328cfffca84503ca',
        '0x3eb52110ced4da0023fb21859db33a42954f7530',
        '0x4dba43d40b869f6ba9f7b0ea5c5ef054debdacc3',
        '0x667663f36ac08e78bbf259f1361f02dc7dad593b',
        'ct9dc895fe5905dc73a2273e70be077bf3e94ea3b7'
    ]
    CUSTODIAN_WALLET_LIST = MEMBER_WALLET_LIST + [
        ASQI_WALLET,
        FOUNDATION_WALLET,
    ]