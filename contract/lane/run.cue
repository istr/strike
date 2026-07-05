// Runtime status types that live in package lane but are not part of the
// lane.yml input schema (that is lane.cue). Generated into
// internal/lane/lane.gen.go.
package lane

import "github.com/istr/strike/contract/primitive"

// #StepResult is the execution metadata one completed step contributes to the
// serialized run status. Debug/CI state-dump shape only; never attestation-
// facing, so its wire form is free to change.
#StepResult: {
	@go(StepResult)
	startedAt: primitive.#Timestamp @go(StartedAt)
	outputs: {
		[string]: string @go(Outputs)
	}
	id:       primitive.#Identifier @go(ID)
	stepType: string                @go(StepType)
	duration: primitive.#Duration   @go(Duration)
	exitCode: int                   @go(ExitCode)
}
