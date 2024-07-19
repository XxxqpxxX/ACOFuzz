import re
import networkx as nx
import matplotlib.pyplot as plt
import solidity_parser


testedge = []
my_dict = {}
var_list = []
func_list = []

def getnode(solfilename):
    contract_code = open(solfilename).read()

    # 解析智能合约代码生成AST
    node = solidity_parser.parse(contract_code)
    return node
def astinfo(node):

    if node.get("type") == "VariableDeclaration":
        var_name = node.get("name")
        var_list.append(var_name)
        my_dict['var'] = var_list

    if node.get("type") == "FunctionDefinition":
        func_name = node.get("name")
        func_list.append(func_name)
        my_dict['func'] = func_list

    for key, value in node.items():
        if isinstance(value, list):
            for item in value:
                astinfo(item)
        elif isinstance(value, dict):
            astinfo(value)

    return func_list,my_dict


def match_txt(cfgfilename):
    pattern = r"\b\d+ -> \d+\b"

    with open(cfgfilename, 'r') as file:
        content = file.read()
        matches = re.findall(pattern, content)
        return matches


def match_txt(cfgfilename):
    pattern = r"\b\d+ -> \d+\b"

    with open(cfgfilename, 'r') as file:
        content = file.read()
        matches = re.findall(pattern, content)
        return matches


def match_func_col(cfgfilename, funclist):
    pattern = r'\s(\d+)\[label="Function name: (.+?)\\l'

    with open(cfgfilename, 'r') as f:
        content = f.read()
        matches = re.findall(pattern, content)


    func_dict = {}
    for match in matches:
        if match[1].split('(')[0] in funclist:
            function_name = match[1].split('(')[0]
            line_number = int(match[0])
            func_dict[line_number] = function_name

    return func_dict

def cfginfo(solfilename,cfgfilename,):
    # 读入智能合约代码

    node = getnode(solfilename)
    nodelist = []
    # 提取cfg的节点与边的信息

     # 替换成你的txt文件路径
    result = match_txt(cfgfilename)
    result = [s.replace(';', '') for s in result]
    func_col = match_func_col(cfgfilename, astinfo(node)[1]['func'])

    for s in result:
        numbers = re.findall(r'\d+', s)  # 使用正则表达式提取数字
        nodelist.extend(numbers)  # 将提取到的数字添加到新列表中

    cfg_node = [int(x) for x in list(set(nodelist))]
    cfg_edge = [[int(num) for num in s.split(' -> ')] for s in result]  # 使用列表推导式将提取到的数字转换为整数类型，并嵌套在新列表中

    nodes = sorted(cfg_node)
    return func_col,cfg_edge,nodes

def cfgmatrix(cfg_edge,nodes):
    # 生成cfg图的邻接矩阵
    num_nodes = len(nodes)

    # 创建100000矩阵
    adjacency_matrix = [[100000] * num_nodes for _ in range(num_nodes)]

    for i in range(len(nodes)):
        for j in range(len(nodes)):
            testedge.append([nodes[i], nodes[j]])

    # 修改存在边的节点的矩阵
    for i in range(0, len(testedge)):
        for j in range(0, len(cfg_edge)):
            if testedge[i] == cfg_edge[j]:
                x = nodes.index(testedge[i][0])
                y = nodes.index(testedge[i][1])
                adjacency_matrix[x][y] = 1
    return adjacency_matrix

def findend(adjacency_matrix,city):
    # 找到所有结束的点
    nodes_done = []
    done = []# 用于保存全为 0 的行号

    for i, row in enumerate(adjacency_matrix):
        if all(x == 100000 for x in row):
            done.append(i)
            nodes_done.append(city[i])

    # 打印结果
    return nodes_done,done
# node = getnode('toy.sol')
# # print(node)
# func_list = astinfo(node)[0]
# # print(func_list)
# print('**********')
# # print(match_func_col('aaa.gv', func_list))
# info = cfginfo('toy.sol','Test.dot')
# martix = cfgmatrix(info[1],info[2])
# # print(findend(martix,info[2]))
# print(martix)
# print('**********')

# print('-----------func---------')
# print(info[0])
# print('-----------edge---------')
# print(info[1])
# print('-----------node---------')
# print(info[2])


# done = findend(martix,info[2])[1]
# print('-----------end_node---------')
# print(done)