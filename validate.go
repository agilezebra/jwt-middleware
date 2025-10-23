package jwt_middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"strings"

	"github.com/agilezebra/jwt-middleware/logger"
	"github.com/danwakefield/fnmatch"
)

// Requirement is the interface for a requirement that can be validated against a value.
type Requirement interface {
	Validate(value any, variables *TemplateVariables) error
}

// RequirementMap is a map of claim names to requirements.
type RequirementMap map[string]Requirement

// ValueRequirement is a requirement for a claim that is a known value.
type ValueRequirement struct {
	value any
}

// TemplateRequirement is a dynamic requirement for a claim that uses a template that needs interpolating per request.
type TemplateRequirement struct {
	template *template.Template
}

// OrRequirement is a requirement for a claim with a list of requirements, any one of which must match.
type OrRequirement struct {
	requirements []Requirement
}

// AndRequirement is a requirement for a claim with a list of requirements, all of which must match.
type AndRequirement struct {
	requirements []Requirement
}

// NewRequirement is the entry point for creating a new Requirement from the require map.
func NewRequirement(value any, group string) Requirement {
	switch value := value.(type) {
	case []any:
		requirements := make([]Requirement, len(value))
		for index, value := range value {
			requirements[index] = NewRequirement(value, group)
		}
		switch group {
		case "$or":
			return OrRequirement{requirements: requirements}
		case "$and":
			return AndRequirement{requirements: requirements}
		default:
			panic(fmt.Sprintf("unknown group: %s", group))
		}
	case map[string]any:
		if len(value) == 1 {
			for key, value := range value {
				if strings.HasPrefix(key, "$") {
					// special case of 1 element maps with a leading $
					return NewRequirement(value, key)
				}
			}
		}

		result := make(RequirementMap, len(value))
		for claim, value := range value {
			result[claim] = NewRequirement(value, "$or")
		}
		return result
	case string:
		if strings.Contains(value, "{{") && strings.Contains(value, "}}") {
			return TemplateRequirement{
				template: NewTemplate(value),
			}
		}
	}
	return ValueRequirement{value: value}
}

// (RequirementMap) Validate is the entry point for validating a JWT claims map (which should be passed in converted to a map[string]any).
// It will also be called recursively for nested maps within.
func (requirements RequirementMap) Validate(value any, variables *TemplateVariables) error {
	claims, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("value must be map[string]any; got %T", value)
	}

outer:
	for claim, validator := range requirements {
		value, ok := claims[claim]
		if ok {
			// Claim is present, simply validate it
			err := validator.Validate(value, variables)
			if err != nil {
				return fmt.Errorf("%s: %w", claim, err)
			}
		} else {
			// Claim is not present, but a wildcard claim may match
			err := fmt.Errorf("claim is not present")
			for pattern, value := range claims {
				if wildcardMatch(pattern, claim) {
					err := validator.Validate(value, variables)
					if err == nil {
						continue outer
					}
				}
			}

			// Claim is not present and no wildcard match found, or a wildcard matched but claim is not valid
			return fmt.Errorf("%s: %w", claim, err)
		}
	}

	// All claims were validated successfully
	return nil
}

// (ValueRequirement)Validate checks value against the requirement, calling back to itself recursively for object and array values.
// variables is required in the interface and passed on recursively but ultimately ignored by ValueRequirement
// having been already interpolated by TemplateRequirement
func (requirement ValueRequirement) Validate(value any, variables *TemplateVariables) error {
	level, verbose := (*variables)["logUnauthorized"]
	switch value := value.(type) {
	case []any:
		for _, value := range value {
			err := requirement.Validate(value, variables)
			if err == nil {
				return nil
			}
		}
	case map[string]any:
		required, ok := requirement.value.(string)
		if ok {
			for claim := range value {
				if wildcardMatch(claim, required) {
					return nil // This is a wildcard match with irrelevant nested value within the required claim
				}
			}
		}
	case string:
		required, ok := requirement.value.(string)
		if ok {
			if wildcardMatch(value, required) {
				return nil
			}
			if verbose {
				logger.Log(level, "claim is not valid: require:%s got:%v", required, value)
			}
		}
	case json.Number:
		switch requirement.value.(type) {
		case int:
			converted, err := value.Int64()
			required := int64(requirement.value.(int))
			if err == nil && converted == required {
				return nil
			}
			if verbose {
				logger.Log(level, "claim is not valid: require:%d got:%v", required, value)
			}
		case float64:
			converted, err := value.Float64()
			required := requirement.value.(float64)
			if err == nil && converted == required {
				return nil
			}
			if verbose {
				logger.Log(level, "claim is not valid: require:%f got:%v", required, value)
			}
		default:
			log.Printf("unsupported requirement type for json.Number comparison: %T %v", requirement.value, requirement.value)
			return fmt.Errorf("unsupported requirement type for json.Number comparison")
		}
	}

	return fmt.Errorf("claim is not valid")
}

// Validate interpolates the requirement template with the given variables and then delegates to ValueRequirement.
func (requirement TemplateRequirement) Validate(value any, variables *TemplateVariables) error {
	var buffer bytes.Buffer
	err := requirement.template.Execute(&buffer, variables)
	if err != nil {
		log.Printf("Error executing template: %s", err)
		return fmt.Errorf("claim is not valid") // return a generic error to avoid leaking information about the template
	}
	return ValueRequirement{value: buffer.String()}.Validate(value, variables)
}

// (OrRequirement) Validate checks if any of the values in the OR list match wth the value
func (requirement OrRequirement) Validate(value any, variables *TemplateVariables) error {
	for _, requirement := range requirement.requirements {
		err := requirement.Validate(value, variables)
		if err == nil {
			return err
		}
	}
	return fmt.Errorf("claim is not valid")
}

func (requirement AndRequirement) Validate(value any, variables *TemplateVariables) error {
	for _, requirement := range requirement.requirements {
		err := requirement.Validate(value, variables)
		if err != nil {
			return err
		}
	}
	return nil
}

// wildcardMatch checks if the claim pattern (which may contain wildcards) matches the required string
func wildcardMatch(pattern string, required string) bool {
	return fnmatch.Match(pattern, required, 0) || pattern == fmt.Sprintf("*.%s", required)
}
