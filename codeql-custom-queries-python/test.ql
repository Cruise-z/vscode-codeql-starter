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
   predicate isAdditionalFlowStep(DataFlow::Node src, DataFlow::Node dest) {
     exists(API::CallNode getattr, API::CallNode setattr, Class cls, string attr|
       getattr = API::builtin("getattr").getACall() and // 获取getattr
       setattr = API::builtin("setattr").getACall() and // 获取setattr
       src = setattr.getArg(2) and // 数据流来源定义为setattr的第三个参数
       dest = getattr and // 数据流去向定义为getattr
       getattr.getArg(0).asExpr().toString() = "self" and // getattr的第一个参数为self
       setattr.getArg(0).asExpr().toString() = "self" and // setattr的第一个参数为self
       // 并且这里要求getattr和setattr的调用函数的定义的类是同一个，也就是self的意义指向是同一个
       exists(Function f1, Function f2 |   
         getattr.asExpr().getScope() = f1 and
         setattr.asExpr().getScope() = f2 and
         f1.getScope() = cls and
         f2.getScope() = cls and
         f1.isMethod() and
         f2.isMethod()
       ) and
       // 并且getattr和setattr的第二个参数的字符串是一样的
       getattr.getArg(1).asExpr().(StringLiteral).getText() = attr and
       setattr.getArg(1).asExpr().(StringLiteral).getText() = attr
     )or exists(API::CallNode int_call | 
       int_call = API::builtin("int").getACall() and
       src= int_call.getArg(0) and
       dest = int_call
     ) 
   }
 }
 
 
 module CalcClassFlow = TaintTracking::Global<CalcClassConfiguration>;
 import CalcClassFlow::PathGraph
  
 from CalcClassFlow::PathNode sourceNode, CalcClassFlow::PathNode sinkNode
 where CalcClassFlow::flowPath(sourceNode, sinkNode)
 select sinkNode.getNode(), sourceNode, sinkNode, "Dangerous eval with $@.", sourceNode.getNode(), "user-provided value"