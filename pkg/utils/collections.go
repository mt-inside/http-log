package utils

import "fmt"

func Map[T, U any](xs []T, f func(T) U) []U {
	ys := make([]U, 0, len(xs))

	for _, x := range xs {
		ys = append(ys, f(x))
	}

	return ys
}

func MapToString[T fmt.Stringer](xs []T) []string {
	return Map(xs, func(x T) string { return x.String() })
}

// Will panic if it's not actually a Stringer (or string)
func MapAnyToString(xs []any) []string {
	return Map(xs, func(x any) string {
		if s, ok := x.(string); ok {
			return s
		} else if s, ok := x.(fmt.Stringer); ok {
			return s.String()
		} else {
			panic(fmt.Errorf("%v is not stringable", x))
		}
	})
}
