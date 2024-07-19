from .checker import Checker
from ...ethereum import *


class access_control(Checker):

    def __init__(self, contract_manager, account_manager):
        super().__init__()
        self.contract_manager = contract_manager
        self.account_manager = account_manager

        self.addresses = []
        for contract in contract_manager.contract_dict.values():
            self.addresses += contract.addresses

        for account in account_manager.accounts:
            self.addresses.append(account.address)


    def check(self, logger):
        for log in logger.logs:
            if log.op == SSTORE:
                if int(log.stack[-2], 16) == 0x0:
                    return True
