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
