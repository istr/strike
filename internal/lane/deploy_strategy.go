package lane

// KubectlVerb returns the kubectl subcommand for the deploy strategy. The switch
// is exhaustive over DeployStrategy, so adding a strategy value to the schema
// forces a decision here instead of a silent passthrough. The trailing return
// handles the value that schema validation and the parse-seam default already
// guarantee is one of the cases above.
func (s DeployStrategy) KubectlVerb() string {
	switch s {
	case deployStrategyApply:
		return "apply"
	case deployStrategyReplace:
		return "replace"
	case deployStrategyRollout:
		return "rollout"
	}
	return string(s)
}
