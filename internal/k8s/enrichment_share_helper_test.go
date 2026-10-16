package k8s

import "reflect"

func reflectPointer(m map[string]string) uintptr { return reflect.ValueOf(m).Pointer() }
