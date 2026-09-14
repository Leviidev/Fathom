// Everything Swift sees of the emulator core.
//
// The core is compiled directly into the app (see the Runtime group in the Xcode
// project), so these symbols are already in the executable at launch -- there is no
// dylib to load and no dlsym anywhere.
#import "fathom_api.h"
