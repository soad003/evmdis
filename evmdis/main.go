package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/soad003/evmdis"
	"io/ioutil"
	"log"
	"os"
	"math/big"
	"encoding/json"
)

const swarmHashLength = 43

var swarmHashProgramTrailer = [...]byte{0x00, 0x29}
var swarmHashHeader = [...]byte{0xa1, 0x65}

func main() {

	withSwarmHash := flag.Bool("swarm", true, "solc adds a reference to the Swarm API description to the generated bytecode, if this flag is set it removes this reference before analysis")
	ctorMode := flag.Bool("ctor", false, "Indicates that the provided bytecode has construction(ctor) code included. (needs to be analyzed seperatly)")
	logging := flag.Bool("log", false, "print logging output")
	calls := flag.Bool("calls", false, "print hardcoded/constant addresses that are called")
	json := flag.Bool("json", false, "generate JSON output, when possible")
	printSwarm := flag.Bool("printSwarm", false, "prints swarm hash if found, only usefull if swarm is set")

	flag.Parse()

	if !*logging {
		log.SetOutput(ioutil.Discard)
	}

	hexdata, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Sprintf("Could not read from stdin: %v", err))
	}

	bytecodeLength := uint64(hex.DecodedLen(len(hexdata)))
	bytecode := make([]byte, bytecodeLength)

	hex.Decode(bytecode, hexdata)

	// detect swarm hash and remove it from bytecode, see http://solidity.readthedocs.io/en/latest/miscellaneous.html?highlight=swarm#encoding-of-the-metadata-hash-in-the-bytecode
	if bytecode[bytecodeLength-1] == swarmHashProgramTrailer[1] &&
		bytecode[bytecodeLength-2] == swarmHashProgramTrailer[0] &&
		bytecode[bytecodeLength-43] == swarmHashHeader[0] &&
		bytecode[bytecodeLength-42] == swarmHashHeader[1] &&
		(*withSwarmHash || *printSwarm) {

		if(*printSwarm && !*json) {
			fmt.Printf("0x%v\n", hex.EncodeToString(bytecode[bytecodeLength-34:bytecodeLength-2]))
		} else if (*printSwarm && *json){
			fmt.Printf("{ \"swarmHash\":\"0x%v\" }\n", hex.EncodeToString(bytecode[bytecodeLength-34:bytecodeLength-2]))
		}
		
		if(*withSwarmHash) {
			bytecodeLength -= swarmHashLength // remove swarm part
		}

	}

	program := evmdis.NewProgram(bytecode[:bytecodeLength])
	if *ctorMode {
		AnalyzeProgram(program, nil, false)
		var codeEntryPoint = FindNextCodeEntryPoint(program)

		if codeEntryPoint == 0 {
			panic("no code entrypoint found in ctor")
		} else if codeEntryPoint >= bytecodeLength {
			panic("code entrypoint outside of currently available code")
		}

		ctor := evmdis.NewProgram(bytecode[:codeEntryPoint])
		code := evmdis.NewProgram(bytecode[codeEntryPoint:bytecodeLength])

		AnalyzeProgram(ctor, nil, *calls)
		AnalyzeProgram(code, ctor, *calls)

		fmt.Println("// # Constructor part -------------------------")
		PrintAnalysisResult(ctor, *calls, *json)
		
		fmt.Println("// # Code part -------------------------")
		PrintAnalysisResult(code, *calls, *json)

	} else {
		AnalyzeProgram(program, nil, *calls)
		PrintAnalysisResult(program, *calls, *json)
	}
}

func FindNextCodeEntryPoint(program *evmdis.Program) uint64 {
	var lastPos uint64 = 0
	for _, block := range program.Blocks {
		for _, instruction := range block.Instructions {
			if instruction.Op == evmdis.CODECOPY {
				var expression evmdis.Expression

				instruction.Annotations.Get(&expression)

				instExpr, ok := expression.(*evmdis.InstructionExpression)
				var arg *big.Int
				if ok {
					arg = instExpr.Arguments[1].Eval()
				} else {
					log.Printf("CODECOPY arg not InstExpr: %v\n", expression)
				}
				

				if arg != nil {
					lastPos = arg.Uint64()
				}
			}
		}
	}
	return lastPos
}

func AnalyzeProgram(program *evmdis.Program, ctor *evmdis.Program, calls bool) {
	if err := evmdis.PerformReachingAnalysis(program); err != nil {
		panic(fmt.Sprintf("Error performing reaching analysis: %v", err))
	}
	evmdis.PerformReachesAnalysis(program)
	evmdis.CreateLabels(program)
	if err := evmdis.BuildExpressions(program); err != nil {
		panic(fmt.Sprintf("Error building expressions: %v", err))
	}

	if calls {
			evmdis.AnnotateCallsWithConstantAddresses(program)
			log.Println("DONE WITH CALLS")
			//evmdis.AnnotateSSTOREsWithConstantValues(program)
			//evmdis.ResolveSLOADWithConstructorConstants(program, ctor)
	}
}


func PrintAnalysisResult(program *evmdis.Program, calls bool, asJson bool) {
	if calls {
		for _, block := range program.Blocks {
			for _, instruction := range block.Instructions {

				var sto *evmdis.StoreOn

				instruction.Annotations.Get(&sto)

				if sto != nil{
					log.Println(sto)
				}

				var call *evmdis.CallOnAddress

				instruction.Annotations.Get(&call)

				if call != nil && asJson {
					r, _ := json.Marshal(call.ToOutput())
					fmt.Println(string(r))
					log.Println(call)
				} else if call != nil{
					fmt.Println(call)
				}

			}
		}

	} else {
		if asJson {
			log.Println("json flag not supported without call flag")
		}
		PrintHighLevelAsm(program)
	}	
}

func PrintHighLevelAsm(program *evmdis.Program) {
	for _, block := range program.Blocks {
		offset := block.Offset

		// Print out the jump label for the block, if there is one
		var label *evmdis.JumpLabel
		block.Annotations.Get(&label)
		if label != nil {
			fmt.Printf("%v\n", label)
		}

		// Print out the stack prestate for this block
		var reaching evmdis.ReachingDefinition
		block.Annotations.Get(&reaching)
		fmt.Printf("# Stack: %v\n", reaching)

		for _, instruction := range block.Instructions {
			var expression evmdis.Expression
			instruction.Annotations.Get(&expression)

			if expression != nil {
				if instruction.Op.StackWrites() == 1 && !instruction.Op.IsDup() {
					fmt.Printf("0x%X\tPUSH(%v)\n", offset, expression)
				} else {
					fmt.Printf("0x%X\t%v\n", offset, expression)
				}
			}
			offset += instruction.Op.OperandSize() + 1
		}
		fmt.Printf("\n")
	}
}

