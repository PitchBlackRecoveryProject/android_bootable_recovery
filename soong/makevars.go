package twrp

import (
	"android/soong/android"
)

func getMakeVars(ctx android.BaseContext, mVar string) string {
	makeVars := ctx.Config().VendorConfig("omniromVarsPlugin")
	var makeVar = ""
	if makeVars.IsSet(mVar) {
		makeVar = makeVars.String(mVar)
	}
	return makeVar
}
