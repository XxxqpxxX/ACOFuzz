from .checker import Checker
from ...ethereum import *
from ilf.ethereum.evm.contract import *

class MultipleSend(Checker):
    def __init__(self, contract_manager, account_manager):
        super().__init__()
        self.contract_manager = contract_manager
        self.account_manager = account_manager
        self.list=[]
        self.path=[]
    def check(self, logger):
        find =False
        send_occurred = False
        CallDepth=0
        address={}
        for log in logger.logs:
            
            if log.op == CALL and int(log.stack[-3], 16) > 0 and int(log.stack[-1], 16) > 0 :
                print(log.stack)
                print('log.stack[-1] is')
                print(log.stack[-1])
                print('log.stack[-2] is')
                print(log.stack[-2])
                print('log.stack[-3] is')
                print(log.stack[-3])
                print('address is')
                print(address)
                if log.stack[-2] in address:
                    find = True
                    if find:
                        return True
                else:
                    address[log.stack[-2]] = True

