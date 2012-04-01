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
// PluginController.h


#ifndef __PluginController_H_
#define __PluginController_H_

#include <vector>
#include <memory>
#include <pro.h>

struct sample_info_t;

class PluginController {
public:
    PluginController();
    ~PluginController();
    void run();

private:
    bool createWindow();
    bool processFunctions();
    void updateWindowContents();
    ea_t createFunctionAt(ea_t address);

private:
   std::unique_ptr<sample_info_t> viewPtr;
   std::vector<ea_t > corruptedFunctions_;
};

#endif //__PluginController_H_
