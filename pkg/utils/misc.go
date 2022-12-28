package utils

func Ternary[T any](test bool, yes T, no T) T {
	if test {
		return yes
	} else {
		return no
	}
}
