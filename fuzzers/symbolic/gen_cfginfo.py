import re
import networkx as nx
import matplotlib.pyplot as plt

import ilf.fuzzers.symbolic.ilfcfg as ilfcfg

node = []
testedge = []

#提取cfg的节点与边的信息
def match_txt(filename):
    pattern = r'.*->.*'

    with open(filename, 'r') as file:
        content = file.read()
        matches = re.findall(pattern, content)
        return matches

filename = 'aaa.gv'  # 替换成你的txt文件路径
# result = match_txt(filename)
# print(result)
# result = [s.replace(';', '') for s in result]
#
# for s in result:
#     numbers = re.findall(r'\d+', s)  # 使用正则表达式提取数字
#     node.extend(numbers)  # 将提取到的数字添加到新列表中
#
# cfg_node = [int(x) for x in list(set(node))]
# cfg_edge = [[int(num) for num in s.split(' -> ')] for s in result]  # 使用列表推导式将提取到的数字转换为整数类型，并嵌套在新列表中
# print(cfg_node)
# print(cfg_edge)
#
# nodes = sorted(cfg_node)
# print(nodes)
#
# #生成cfg图的邻接矩阵
# num_nodes = len(nodes)
#
# # 创建零矩阵
# adjacency_matrix = [[0] * num_nodes for _ in range(num_nodes)]
#
# for i in range(len(nodes)):
#     for j in range(len(nodes)):
#         testedge.append([nodes[i], nodes[j]])
#
# #修改存在边的节点的矩阵
# for i in range(0,len(testedge)):
#     for j in range(0,len(cfg_edge)):
#         if testedge[i] == cfg_edge[j]:
#             x = nodes.index(testedge[i][0])
#             y = nodes.index(testedge[i][1])
#             adjacency_matrix[x][y] = 1
# print(adjacency_matrix)


#显示图片
cfg = nx.DiGraph()
cfg.add_edges_from(ilfcfg.cfginfo('toy.sol','aaa.gv')[1])

pos = nx.spring_layout(cfg)
nx.draw_networkx(cfg, pos, with_labels = True, node_color='lightblue', edge_color='red')
plt.show()
