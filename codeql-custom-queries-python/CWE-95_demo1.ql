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
 
 module CodeInjectionConfiguration implements DataFlow::ConfigSig {
   // Define a predicate for identifying user-provided input as the source
   predicate isSource(DataFlow::Node source) {
     source = API::builtin("input").getACall() or
              exists(DataFlow::CallCfgNode user_input |
                 user_input.getFunction().toString() = "get_input" and
                 source = user_input.getArg(0)
              )
   }
 
   // Define a predicate for identifying the eval function call as the sink
   predicate isSink(DataFlow::Node sink) {
     exists(DataFlow::CallCfgNode call |
       call = API::builtin("eval").getACall() and
       sink = call.getArg(0)
     )
   }
 }
 
 module CodeInjectionFlow = TaintTracking::Global<CodeInjectionConfiguration>;
 import CodeInjectionFlow::PathGraph
 
 from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
 where CodeInjectionFlow::flowPath(source, sink)
 select sink.getNode(), source, sink, "This code execution depends on a $@.", source.getNode(),
   "user-provided value"
 