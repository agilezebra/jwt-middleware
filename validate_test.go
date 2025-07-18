// These tests test only corner error cases in validate.go.
// Correctness of all validation functionality is tested in jwt_test.go.
package jwt_middleware

import (
	"testing"
)

func TestNewRequirement(tester *testing.T) {
	defer func() {
		if recover() == nil {
			tester.Errorf("NewRequirement() did not panic")
		}
	}()

	// This should panic
	NewRequirement([]any{"user", "admin"}, "$other")
}

func TestValidatorMap(tester *testing.T) {
	variables := TemplateVariables{"authority": "test.example.com"}
	requirementMap := make(RequirementMap)
	requirementMap["role"] = ValueRequirement{value: "user"}

	result := requirementMap.Validate(false, &variables)
	if result.Error() != "value must be map[string]any; got bool" {
		tester.Errorf("RequirementMap.Validate() = %v; want error", result)
	}
}
