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
  Address     *big.Int `json:"address"`
  Call        Instruction `json:"-"`
  ResolvedSLOAD bool `json:"isResolvedCtorConst,"`
  Trace       *TraceResult `json:"-"`
}

type CallOnAddressOut struct {
  Address             *string `json:"address"`
  CallType            string `json:"callType"`
  IsResolvedCtorConst bool `json:"isResolvedCtorConst,bool"`
  DependsOnStorage    bool `json:"dependsOnStorage,bool"`
  DependsOnCalldata   bool` json:"dependsOnCalldata,bool"`
  DependsOnUnknown   bool` json:"dependsOnUnknown,bool"`
}

type StoreOn struct {
  ToAddress       *big.Int `json:"to"`
  Data            *big.Int `json:"data"`
  TraceToAddress  *TraceResult `json:"-"`
  TraceData       *TraceResult `json:"-"`
}

func (self *TraceResult) String() string {
  return fmt.Sprintf("%v(0x%X)", self.Inst.Op, self.Arg)
}

func (self *CallOnAddress) String() string {
  if self.DependsOnCalldata() {
    return fmt.Sprintf("CALL depends on CALLDATA 0x%X", self.Address)
  } else if self.DependsOnStorage() {
    return fmt.Sprintf("CALL depends on SLOAD 0x%X", self.Address)
  } else if self.FoundConst() {
    return fmt.Sprintf("CALL on 0x%X", self.Address)
  } else {
    return fmt.Sprintf("CALL depends on unknown", self.Address)
  }
}

func (self *CallOnAddress) DependsOnStorage() bool {
  if self.Trace == nil {
    return false
  }
  return self.Trace.Inst.Op == SLOAD && !self.ResolvedSLOAD
}

func (self *CallOnAddress) DependsOnCalldata() bool {
  if self.Trace == nil {
    return false
  }
  return  self.Trace.Inst.Op == CALLDATALOAD
}

func (self *CallOnAddress) DependsOnUnknown() bool {
  return  !self.FoundConst() && self.Trace == nil
}

func (self *CallOnAddress) FoundConst() bool {
  return self.Address != nil
}


func (self *CallOnAddress) ToOutput() *CallOnAddressOut {
  t := new(CallOnAddressOut)
  if self.Address != nil {
    bla := fmt.Sprintf("0x%X", self.Address)
    t.Address = &bla
  }
  t.IsResolvedCtorConst = self.ResolvedSLOAD
  t.CallType = self.Call.Op.String()
  t.DependsOnStorage = self.DependsOnStorage()
  t.DependsOnCalldata = self.DependsOnCalldata()
  t.DependsOnUnknown = self.DependsOnUnknown()

  if t.DependsOnCalldata || t.DependsOnStorage {
    t.Address = nil
  }
  return t
}

func (self *StoreOn) String() string {
  if self.TraceData.Inst.Op == CALLDATALOAD {
    return fmt.Sprintf("STORE CALLDATA 0x%X to 0x%X", self.Data, self.ToAddress)
  } else if self.TraceData.Inst.Op == SLOAD {
    return fmt.Sprintf("STORE SLOAD 0x%X to 0x%X", self.Data, self.ToAddress)
  } else {
    return fmt.Sprintf("STORE 0x%X to 0x%X", self.Data, self.ToAddress)
  }
}

func AnnotateCallsWithConstantAddresses(program *Program) { 
  for _, block := range program.Blocks {
    for _, instruction := range block.Instructions {
      if instruction.Op == CALL ||
          instruction.Op == CALLCODE ||
          instruction.Op == DELEGATECALL {
          
          log.Printf("Trace back call %v\n", instruction)

          tr := traceBack(getCreatorInstructionOfNthStackElement(&instruction, 1), findAddressOrDependance, maxTraceDepth)

          adr := new(CallOnAddress)
          
          adr.ResolvedSLOAD = false
          adr.Call = instruction
          if tr != nil {
            adr.Address = tr.Arg
            adr.Trace = tr
            log.Println(tr)
          }
          instruction.Annotations.Set(&adr)
      
      }
    }
  }
}

func AnnotateSSTOREsWithConstantValues(program *Program) {
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
          sto.TraceToAddress = trTo
          sto.TraceData = trData
          instruction.Annotations.Set(&sto)
          log.Println(trTo)
          log.Println(trData)
        }

      }
    }
  }
}

func getConstantSSTORESs(program *Program) []*StoreOn {
  var res []*StoreOn

  for _, block := range program.Blocks {
    for _, instruction := range block.Instructions {
      var sto *StoreOn

      instruction.Annotations.Get(&sto)

      if sto != nil{
        res = append(res, sto)
      }   
    }
  }
  return res
}

func getCallsOnAddresses(program *Program) []*CallOnAddress {
  var res []*CallOnAddress

  for _, block := range program.Blocks {
    for _, instruction := range block.Instructions {
      var call *CallOnAddress

      instruction.Annotations.Get(&call)

      if call != nil{
        res = append(res, call)
      }   
    }
  }
  return res
}

func findSStoreOn(stores []*StoreOn, adr *big.Int) *StoreOn {
  for _, s := range stores {
    if adr != nil && s.ToAddress != nil && s.ToAddress.Cmp(adr) == 0 {
      return s
    }
  }
  return nil
}

func ResolveSLOADWithConstructorConstants(program *Program, ctor *Program) {
  if ctor == nil { return }
  var SSTORESCtor = getConstantSSTORESs(ctor)
  var calls = getCallsOnAddresses(program)
  var SSTORES = getConstantSSTORESs(program)

  for _, c := range calls {
    if c.DependsOnStorage() {
        ctorStore := findSStoreOn(SSTORESCtor, c.Trace.Arg)
        bodyStore := findSStoreOn(SSTORES, c.Trace.Arg)
        bodyUnknownStore := findSStoreOn(SSTORES, nil)

        if ctorStore != nil && bodyStore == nil && bodyUnknownStore == nil {
          c.Address = ctorStore.Data
          c.ResolvedSLOAD = true
        }
    }
  }
}

func getCreatorInstructionOfNthStackElement(instruction *Instruction, argNr int) []*Instruction {
  var reaching ReachingDefinition
  instruction.Annotations.Get(&reaching)

  if reaching != nil {
    res := make([]*Instruction, 0)
    for k, _ := range reaching[argNr] {
      // IP to loc that created the address stack portion
      log.Println("%v\n", k.Get())
      res = append(res, k.Get())
    }

    return res
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

    if(res.SubTrace != nil) {
      res.Arg = res.SubTrace.Arg
    }  
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

func traceBack(instructions []*Instruction, filter TraceFilter, maxDepth int) *TraceResult {
  for _, instruction := range instructions {
      if maxDepth <= 0 || instruction == nil { return nil }
      res, done := filter(instruction)

      if done {
        return res
      }
      
      res = traceBackChildren(instruction, filter, maxDepth)
      if res != nil {
        return res
      }
  }
  return nil
}

func traceBackChildren(instruction *Instruction, filter TraceFilter, maxDepth int) *TraceResult {
  for i := 0; i < instruction.Op.StackReads(); i++ { 

    tr := traceBack(getCreatorInstructionOfNthStackElement(instruction, i), filter, maxDepth - 1)
    if(tr != nil) {
      return tr
    }
  }
  return nil
}