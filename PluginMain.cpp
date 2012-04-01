// Copyright devnrev, 2012
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// PluginMain.cpp

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <vector>
#include "PluginController.h"


std::unique_ptr<PluginController > pluginController;

int IDAP_init(void) {
    // Only support x86 architecture
    if (strncmp(inf.procName, "metapc", 8) != 0) {
        warning("Only x86 binary type supported, sorry.");
        return PLUGIN_SKIP;
    }
    std::unique_ptr<PluginController> procInst(new PluginController());
    pluginController = std::move(procInst);
    return PLUGIN_KEEP;
}

void IDAP_term(void) {

    return;
}

void IDAP_run(int arg) {
    pluginController->run();
    return;
}

char IDAP_comment[] = "Function definer";
char IDAP_help[] =
        "Searches functions which aren't recognized by IDA and defines them\n";
char IDAP_name[] = "Function definer";
char IDAP_hotkey[] = "Alt-M";
plugin_t PLUGIN =
        {
                IDP_INTERFACE_VERSION,
                0,
                IDAP_init,
                IDAP_term,
                IDAP_run,
                IDAP_comment,
                IDAP_help,
                IDAP_name,
                IDAP_hotkey
        };