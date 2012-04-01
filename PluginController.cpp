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
// PluginController.cpp

#include "PluginController.h"
#include "PluginHeader.h"
#include <ida.hpp>
#include <allins.hpp>
#include <idp.hpp>

PluginController::PluginController() {

}

PluginController::~PluginController() {

}

void PluginController::run() {
#ifdef SHOW_CONTENT
    if (createWindow()) {
#endif
    if (processFunctions()) {

    }
#ifdef SHOW_CONTENT
        updateWindowContents();
    }
#endif
}

void PluginController::updateWindowContents() {
    simpleline_place_t s1;
    simpleline_place_t s2(viewPtr->content.size() ? viewPtr->content.size() - 1 : 0);
    if (viewPtr->opened) {
        switchto_tform(viewPtr->form, true);
    } else {
        viewPtr->cv = create_custom_viewer("", reinterpret_cast<TWinControl *>(viewPtr->form), &s1, &s2, &s1, 0, &viewPtr->content);
        open_tform(viewPtr->form, FORM_TAB| FORM_MENU | FORM_RESTORE);
        viewPtr->opened = true;
    }
}

bool PluginController::createWindow() {
    if (viewPtr != nullptr) {
        viewPtr->content.clear();
        return true;
    }
    HWND hwnd = NULL;
    // try to create the custom view
    const char mycaption[17] = "Unrecog Funcs";
    TForm *form = create_tform(mycaption, &hwnd);

    // if creation failed, maybe it already exists
    // this doesn't seem to work with the new QT GUI, only with the old one
    if (hwnd == NULL) {
        return false;
    }
    // allocate block to hold info about our sample view
    std::unique_ptr<sample_info_t > si(new sample_info_t(form));
    viewPtr = std::move(si);
    return true;
}

bool PluginController::processFunctions() {
    //retrieve TEXT segment
    segment_t *textSeg = get_segm_by_name("__text");
    if (textSeg != NULL) {

        ea_t cursorPos = textSeg->startEA;
        ea_t endPos = textSeg->endEA;
       // ea_t cursorPos = get_screen_ea();
       // ea_t endPos = cursorPos + 0x1000;
       // if (endPos > textSeg->endEA) endPos = textSeg->endEA;
        while (cursorPos < endPos) {
            if (!decode_insn(cursorPos)) {
                cursorPos += 0x1;
                continue;
            }

            if (cmd.itype == NN_push) {
                op_t operand = cmd.Operands[0];
                if (operand.is_reg(5)) {
                    ea_t lookAheadCursor = cursorPos + cmd.size;
                    if (!decode_insn(lookAheadCursor)) {
                        cursorPos = lookAheadCursor + 0x1;
                        continue;
                    }
                    switch (cmd.itype) {
                        case NN_mov:
                        {
                            op_t operandOne = cmd.Operands[0];
                            op_t operandTwo = cmd.Operands[1];
                            if (operandOne.is_reg(5) && operandTwo.is_reg(4)) {
                                cursorPos = createFunctionAt(cursorPos);
                            }
                            break;
                        }
                        case NN_push:
                        {
                            if (!cmd.Operands[0].is_reg(5)) {
                                cursorPos = createFunctionAt(cursorPos);
                            }
                            break;
                        }
                        case NN_sub:
                        {
                            op_t operandOne = cmd.Operands[0];
                            op_t operandTwo = cmd.Operands[1];
                            if (operandOne.is_reg(4) && (operandTwo.type == o_imm)) {
                                cursorPos = createFunctionAt(cursorPos);
                            }
                            break;
                        }
                        default:

                            break;
                    }
                    cursorPos = lookAheadCursor + cmd.size;
                    continue;
                }
            }
            flags_t codeFlag = get_flags_novalue(cursorPos);
            if (!isCode(codeFlag)) {
                cursorPos += 1;
            } else {
                cursorPos += cmd.size;
            }

        }
        return true;
    }
    return false;
}

ea_t PluginController::createFunctionAt(ea_t address) {
    flags_t codeFlag = get_flags_novalue(address);
    if (!isCode(codeFlag)) {
        do_unknown(address, DOUNK_SIMPLE);
        if (create_insn(address) == 0) {
            return address + 1;
        }
    }

#ifdef SHOW_CONTENT
    char buf[100];
 #endif
    func_t *func = get_func(address);
    if (func != NULL) {
        //qsnprintf(buf, sizeof(buf), "Function found at: %x - end: %x - size: %x\n", func->startEA, func->endEA, func->size());
        //viewPtr->content.push_back(buf);
        return func->endEA;
    }
    func_t newFunc;
    newFunc.startEA = address;
    int res = find_func_bounds(address, &newFunc, FIND_FUNC_DEFINE);
    if (res == FIND_FUNC_OK) {
        if (add_func(newFunc.startEA, newFunc.endEA)) {
#ifdef SHOW_CONTENT
            qsnprintf(buf, sizeof(buf), "Function created at: %x - end: %x - size: %x\n", newFunc.startEA, newFunc.endEA, newFunc.size());
            viewPtr->content.push_back(buf);
   #endif
        } else {
#ifdef SHOW_CONTENT
            qsnprintf(buf, sizeof(buf), "\"Function could not be created at: %x - end: %x\n", newFunc.startEA);
            viewPtr->content.push_back(buf);
            corruptedFunctions_.push_back(newFunc.startEA);

   #endif

        }
    } else {
        if (res == FIND_FUNC_UNDEF) {
#ifdef SHOW_CONTENT
            qsnprintf(buf, sizeof(buf), "\"Error derterming function bounds for function at: %x - end: %x\n", newFunc.startEA, newFunc.endEA);
            viewPtr->content.push_back(buf);
            corruptedFunctions_.push_back(newFunc.startEA);
   #endif
            return address + 1;
        }
    }
    return newFunc.endEA;
}