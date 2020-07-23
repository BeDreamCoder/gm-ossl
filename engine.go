/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm_ossl

/*
#include "openssl/engine.h"
*/
import "C"

type Engine struct {
	e *C.ENGINE
}

func engineRef(e *Engine) *C.ENGINE {
	if e == nil {
		return nil
	}
	return e.e
}
