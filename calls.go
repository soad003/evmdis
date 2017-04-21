package evmdis

import (
  "fmt"
  //"strings"
  "math/big"
  "log"
)

const maxTraceDepth = 1024

type TraceFilter func(*Instruction) (*TraceResult, bool)

type TraceResult struct {
  Inst        *Instruction
  Arg         *big.Int
  SubTrace    *TraceResult
}

type CallOnAddress struct {
  Address     *big.Int
  Trace       *TraceResult
}

type StoreOn struct {
  ToAddress       *big.Int
  Data            *big.Int
  TraceToAddress  *TraceResult
  TraceData       *TraceResult
}

func (self *TraceResult) String() string {
  return fmt.Sprintf("%v(0x%X)", self.Inst.Op, self.Arg)
}

func (self *CallOnAddress) String() string {
  if self.Trace.Inst.Op == CALLDATALOAD {
    return fmt.Sprintf("CALL depends on CALLDATA 0x%X", self.Address)
  } else if self.Trace.Inst.Op == SLOAD {
    return fmt.Sprintf("CALL depends on SLOAD 0x%X", self.Address)
  } else {
    return fmt.Sprintf("CALL on 0x%X", self.Address)
  }
}

func (self *StoreOn) String() string {
  return fmt.Sprintf("STORE 0x%X to 0x%X", self.Data, self.ToAddress)
}

func FindCalls(program *Program) { 
  for _, block := range program.Blocks {
    for _, instruction := range block.Instructions {
      if instruction.Op == CALL ||
          instruction.Op == CALLCODE ||
          instruction.Op == DELEGATECALL {
          
          log.Printf("Trace back call %v\n", instruction)

          tr := traceBack(getCreatorInstructionOfNthStackElement(&instruction, 1), findAddressOrDependance, maxTraceDepth)

          if tr != nil {
            adr := new(CallOnAddress)
            adr.Address = tr.Arg
            adr.Trace = tr
            instruction.Annotations.Set(&adr)
            log.Println(tr)
          }
      
      }
    }
  }
}

func FindSSTOREs(program *Program) {
  for _, block := range program.Blocks {
    for _, instruction := range block.Instructions {
      if instruction.Op == SSTORE {

        log.Printf("Trace back SSTORE %v\n", instruction)

        trData := traceBack(getCreatorInstructionOfNthStackElement(&instruction, 1), findAddressOrDependance, maxTraceDepth)
        
        trTo := traceBack(getCreatorInstructionOfNthStackElement(&instruction, 0), findNextPushFilter, maxTraceDepth)
        
        if trTo != nil && trData != nil{
          sto := new(StoreOn)
          sto.ToAddress = trTo.Arg
          sto.Data = trData.Arg
          sto.TraceToAddress = trData
          sto.TraceData = trTo
          instruction.Annotations.Set(&sto)
          log.Println(trTo)
          log.Println(trData)
        }

      }
    }
  }
}

func getCreatorInstructionOfNthStackElement(instruction *Instruction, argNr int) *Instruction {
  var reaching ReachingDefinition
  instruction.Annotations.Get(&reaching)

  if reaching != nil {
    // IP to loc that created the address stack portion
    var p *InstructionPointer = reaching[argNr].First()

    var inst = p.Get()

    return inst
  }
  return nil
}

func findAddressOrDependance(inst *Instruction) (*TraceResult, bool) {
  var maskingAddress = big.NewInt(0)
  maskingAddress.SetString("ffffffffffffffffffffffffffffffffffffffff", 16)
  if(inst.Op == PUSH20 && inst.Arg.Cmp(maskingAddress) != 0) {
    res := new(TraceResult)
    res.Inst = inst
    res.Arg = inst.Arg

    return res, true
  } else if (inst.Op == SLOAD || inst.Op == CALLDATALOAD) {
    res := new(TraceResult)
    res.Inst = inst
    
    res.SubTrace = traceBackChildren(inst, findNextPushFilter, 2)

    res.Arg = res.SubTrace.Arg
    return res, true
  }
  return nil, false
}

func findNextPushFilter(inst *Instruction) (*TraceResult, bool) {
  if(inst.Op.IsPush()) {
    res := new(TraceResult)
    res.Inst = inst
    res.Arg = inst.Arg

    return res, true
  }
  return nil, false
}

func traceBack(instruction *Instruction, filter TraceFilter, maxDepth int) *TraceResult {
  if maxDepth <= 0 || instruction == nil { return nil }
  res, done := filter(instruction)

  if done {
    return res
  }
  
  return traceBackChildren(instruction, filter, maxDepth)
}

func traceBackChildren(instruction *Instruction, filter TraceFilter, maxDepth int) *TraceResult {
  for i := 0; i < instruction.Op.StackReads(); i++ {
    var inst = getCreatorInstructionOfNthStackElement(instruction, i)

    tr := traceBack(inst, filter, maxDepth - 1)
    if(tr != nil) {
      return tr
    }
  }
  return nil
}