/**
 * This is an automatically generated file
 * @author Csome
 * @name Hello world
 * @kind path-problem
 * @problem.severity warning
 * @id python1
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
 
module CalcClassConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = API::builtin("input").getACall()
  }
 
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::AttrWrite attrWrite |
      // 查找属性写操作，检查是否是 'part1' 属性
      attrWrite.getAttributeName() = "part1" and
      sink = attrWrite
    )
  }
}
 
module CalcClassFlow = TaintTracking::Global<CalcClassConfiguration>;
import CalcClassFlow::PathGraph
 
from CalcClassFlow::PathNode sourceNode, CalcClassFlow::PathNode sinkNode
 where CalcClassFlow::flowPath(sourceNode, sinkNode)
select sinkNode.getNode(), sourceNode, sinkNode, "Dangerous eval with $@.", sourceNode.getNode(), "user-provided value"