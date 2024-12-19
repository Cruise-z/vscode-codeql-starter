/**
 * @name Code injection
 * @description Interpreting unsanitized user input as code allows a malicious user to perform arbitrary
 *              code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @sub-severity high
 * @precision high
 * @id py/code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
 
module CalcClassConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = API::builtin("input").getACall() or
    exists(DataFlow::CallCfgNode user_input |
       user_input.getFunction().toString() = "get_input" and
       source = user_input.getArg(0)
    )
  }
 
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call = API::builtin("eval").getACall() and
      sink = call.getArg(0)
    )
  }
  predicate isAdditionalFlowStep(DataFlow::Node start, DataFlow::Node dest) {
    exists(API::CallNode int_call | //对应第一个条件，将int()转换部分的数据流补充进来
        int_call = API::builtin("int").getACall() and
        start= int_call.getArg(0) and
        dest = int_call
    ) or
    exists(API::CallNode getattr, API::CallNode setattr, Class cls, string attr1, string attr2|
      getattr = API::builtin("getattr").getACall() and //定位getattr函数调用点
      setattr = API::builtin("setattr").getACall() and //定位setattr函数调用点
      start = setattr.getArg(2) and //数据流来源为setattr动态属性的第三个参数
      dest = getattr and // 数据流去向为getattr函数
      //getattr和setattr的前两个参数保证相同
      getattr.getArg(0).asExpr().toString() = attr1 and
      setattr.getArg(0).asExpr().toString() = attr1 and
      getattr.getArg(1).asExpr().(StringLiteral).getText() = attr2 and
      setattr.getArg(1).asExpr().(StringLiteral).getText() = attr2 and
      //getattr和setattr所属父类均为ExprProcessor
      exists(Function f1, Function f2 |   
        getattr.asExpr().getScope() = f1 and
        setattr.asExpr().getScope() = f2 and
        f1.getScope() = cls and
        f2.getScope() = cls and
        f1.isMethod() and
        f2.isMethod()
      )
    )
  }
}


module CalcClassFlow = TaintTracking::Global<CalcClassConfiguration>;
import CalcClassFlow::PathGraph
 
from CalcClassFlow::PathNode sourceNode, CalcClassFlow::PathNode sinkNode
where CalcClassFlow::flowPath(sourceNode, sinkNode)
select sinkNode.getNode(), sourceNode, sinkNode, "Dangerous eval with $@.", sourceNode.getNode(), "user-provided value"