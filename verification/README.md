UID2124 独立复现资料。Windows Python3.14.3，未容器化，依赖见dependency-lock.stdout.log。冻结仓库根置于PYTHONPATH；python verification/verification/strict-wire-r1/test_acceptance.py：36项33通过、2失败、1错误。所有Packet序列化再解析，无网卡发包。模型新增37项UTscapy用例、原有inet6.uts选择385-393,395-397共12项独立复跑通过，均有原始日志，不把模型报告的完整512/12算成本轮独立结果。异常来自冻结_rebuild的16位plen打包，夹具每个分片本身合法；跨片DestinationOptions后的嵌套Fragment及M0后续M1均实际返回数据报。demo直接展示上述三类问题，exit1。冻结源码和原轨未修改。

冻结产物提交：https://github.com/9873199/ipv6-fragment-strict-reassembly/commit/61ce7752993794142efcd7523d0e8722a29f2478
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
