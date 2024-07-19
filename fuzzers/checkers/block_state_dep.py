from .checker import Checker
from ...ethereum import *
from ilf.ethereum.evm.contract import *

class BlockStateDep(Checker):

    def __init__(self, contract_manager, account_manager):
        super().__init__()
        self.contract_manager = contract_manager
        self.account_manager = account_manager

        self.list=[]
        self.path=[]
    def check(self, logger):
        block_state_op_idx = -1
        find =False
        for i, log in enumerate(logger.logs):
            if log.op in (COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, BLOCKHASH):
                block_state_op_idx = i
                break

        if block_state_op_idx == -1:
            return False

        last_send_ether_idx = -1
        for i in range(block_state_op_idx, len(logger.logs)):
            log = logger.logs[i]
            if log.op == CREATE:
                value = int(log.stack[-1], 16)
                if value > 0:
                    last_send_ether_idx = max(last_send_ether_idx, i)
            elif log.op in (CALL, CALLCODE):
                value = int(log.stack[-3], 16)
                if value > 0:
                    last_send_ether_idx = max(last_send_ether_idx, i)

        if last_send_ether_idx == -1:
            return False

        for i in range(block_state_op_idx, last_send_ether_idx + 1):
            log = logger.logs[i]
            if log.op == CREATE:
                value = int(log.stack[-1], 16)
                if value == 0:
                    continue

                try:
                    _, value_from_block = logger.trace_log_stack(i-1, -1)
                    if value_from_block:
                        find=True
                        if find:
                            return True

                except RecursionError:
                    pass
            elif log.op in (CALL, CALLCODE):
                value = int(log.stack[-3], 16)
                if value == 0:
                    continue

                try:
                    _, value_from_block = logger.trace_log_stack(i-1, -3)
                    if value_from_block:
                        find=True
                        if find:
                            return True
                except RecursionError:
                    continue
            elif log.op == JUMPI:
                try:
                    _, value_from_block = logger.trace_log_stack(i-1, -2)
                    if value_from_block:
                        find=True
                        if find:
                            return True
                except RecursionError:
                    continue

        def get_taint(val):
            t = Taint(val)  # 初始污点
            taint_func = t.taint
            taint_func([COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, BLOCKHASH])
            return t

        Tfind = False
        # 检查日志中是否存在与块状态相关的操作
        for i, log in enumerate(logger.logs):
            # 获取与块状态相关的记录并设置污点
            if log.op in (COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, BLOCKHASH):
                value = int(log.stack[-1], 16)
                # 定义初始污点和追踪函数
                T = get_taint(value)
                taint_func = T.taint
                # 从当前操作向下追踪污染的值传递路径（即污染值是否流入CALL或JUMPI的操作数中）
                for j in range(i, len(logger.logs)):
                    if logger.logs[j].op in (CALL, CALLCODE):
                        # 监视污染是否流入CALL的操作数（即方法参数）
                        taint_func(logger.logs[j].stack[-1]) 
                        if T.is_tainted(logger.logs[j].stack[-3]):
                            Tfind = True
                            if Tfind:
                                return True 
                    elif logger.logs[j].op == JUMPI:
                        # 监视污染是否流入JUMPI的操作数
                        taint_func(logger.logs[j].stack[-2])
                        if T.is_tainted(logger.logs[j].stack[-2]):
                            Tfind = True
                            if Tfind:
                                return True 

                    

        return False

class Taint:
    def __init__(self, val):
        self.tainted = {val}
        self.trace = {}

    def taint(self, sources):
        for source in sources:
            try:
                if source in self.trace:
                    self.tainted |= self.trace[source]
                else:
                    self.trace[source] = self.tainted.copy()
            except TypeError:
                pass

    def is_tainted(self, var):
        for key in self.trace:
            if var in self.trace[key]:
                return True
        return var in self.tainted
