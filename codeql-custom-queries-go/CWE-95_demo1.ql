/**
 * This is an automatically generated file
 * @author Csome
 * @name muchmorecomplicated
 * @kind path-problem
 * @problem.severity warning
 * @id go1
 */

 import go
 import semmle.go.Scopes
// import semmle.go.dataflow.internal.DataFlowNodes
 
 module MyConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 认为入口点是 func (hs *HTTPServer) xxxxx(c *models.ReqContext) response.Response 
    // 这种定义的参数c
    exists(Method f,  Parameter p| 
      f.getReceiverBaseType().getName() = "HTTPServer" and
      f.getParameter(0) = p and
      p.getType().(PointerType).getBaseType().getName() = "ReqContext" and
      source.asExpr() = p.getAReference()
   )
  }
 
   predicate isSink(DataFlow::Node sink) {
    // 污点是ioutil.ReadFile(path)的path
    exists(CallExpr call | 
      call.getTarget().hasQualifiedName("io/ioutil", "ReadFile") and
      sink.asExpr() = call.getArgument(0)
    )
   }

   predicate isAdditionalFlowStep(DataFlow::Node src, DataFlow::Node dest) {
    // 由于第三方库的问题
    // 需要增加c -> c.Params(xxxx)这条边
    // 这里泛化认为 c -> c.Func(xxx)或者c -> c.xxxx的边
    exists(SelectorExpr tmp, Expr a |
      dest.asExpr() = tmp.getParent() and
      a = tmp.getBase() and
      a.getType().(PointerType).getBaseType().getName() = "ReqContext" and
      src.asExpr() = a
    )
   }

 }
 

 module MyClassFlow = TaintTracking::Global<MyConfiguration>;
 import MyClassFlow::PathGraph
 
from MyClassFlow::PathNode sourceNode, MyClassFlow::PathNode sinkNode
 where MyClassFlow::flowPath(sourceNode, sinkNode)
select sinkNode.getNode(), sourceNode, sinkNode, "Path $@.", sourceNode.getNode(), "user-provided value"