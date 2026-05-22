// SPDX-License-Identifier: MIT
// (c) Dennis Marttinen, Veeti Poutsalo 2026

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// newValidator builds a validator whose `file` and `dir` tag handlers resolve
// non-absolute paths against baseDir. Passing an empty baseDir falls back to
// cwd. This lets Load validate on-disk paths from the config file's directory
// without changing the process working directory.
func newValidator(baseDir string) *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())

	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		tag := fld.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			return fld.Name
		}
		return strings.SplitN(tag, ",", 2)[0]
	})

	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) || baseDir == "" {
			return p
		}
		return filepath.Join(baseDir, p)
	}

	mustRegister(v, "file", func(fl validator.FieldLevel) bool {
		st, err := os.Stat(resolve(fl.Field().String()))
		return err == nil && !st.IsDir()
	})
	mustRegister(v, "dir", func(fl validator.FieldLevel) bool {
		st, err := os.Stat(resolve(fl.Field().String()))
		return err == nil && st.IsDir()
	})

	return v
}

func mustRegister(v *validator.Validate, tag string, fn validator.Func) {
	if err := v.RegisterValidation(tag, fn); err != nil {
		panic(fmt.Errorf("register validator %q: %w", tag, err))
	}
}

func formatErrors(err error) error {
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		return err
	}
	var b strings.Builder
	b.WriteString("invalid configuration:")
	for _, fe := range verrs {
		b.WriteString("\n  ")
		b.WriteString(formatField(fe))
	}
	return errors.New(b.String())
}

func formatField(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s: required", fe.Namespace())
	case "required_without":
		return fmt.Sprintf("%s: required when %s is not set", fe.Namespace(), fe.Param())
	case "required_if":
		return fmt.Sprintf("%s: required when %s", fe.Namespace(), fe.Param())
	case "file":
		return fmt.Sprintf("%s: file not found: %v", fe.Namespace(), fe.Value())
	case "dir":
		return fmt.Sprintf("%s: directory not found: %v", fe.Namespace(), fe.Value())
	case "unique":
		return fmt.Sprintf("%s: duplicates not allowed", fe.Namespace())
	case "cidr":
		return fmt.Sprintf("%s: not a valid CIDR: %v", fe.Namespace(), fe.Value())
	case "min":
		return fmt.Sprintf("%s: must have at least %s entries", fe.Namespace(), fe.Param())
	default:
		return fmt.Sprintf("%s: failed %q (got %v)", fe.Namespace(), fe.Tag(), fe.Value())
	}
}
