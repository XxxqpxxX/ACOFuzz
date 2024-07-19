from .checker import Checker
from ilf.ethereum.evm.contract import *

class Locking(Checker):

    def __init__(self, contract_manager, account_manager):
        super().__init__()
        self.contract_manager = contract_manager
        self.account_manager = account_manager
        self.list=[]
        self.path=[]
    def check(self, logger):
        find =False
        can_send_ether = self.contract_manager[logger.tx.contract].can_send_ether
        can_receive_ether = self.contract_manager[logger.tx.contract].can_receive_ether

        return can_receive_ether and not can_send_ether and logger.contract_receive_ether
