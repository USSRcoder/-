""" Rename uservars, based on its Type

Author: Fedr 
Date: 04.03.2023
Version: IDA 7.2 (python 2.7)

This write based on vds4 example that comes with hexrays sdk. Ugly code, never write on python something before )
"""

import idautils
import idaapi
import idc
import traceback

def is_default_lvar_t(str):
    if (str==""):
        return False;
    result = True;
    if (str[0]=="v"):
        for i in range(1,len(str)):
            if (str[i].isdigit() == False):
                result = False;
                break
    else:
        result = False;
    
    return result;

def lvar_t_newname(tif, n):
    rname = "";
    if (tif[len(tif)-1]=="*"):
        rname += "P";
    if (tif[len(tif)-1]=="]"):
        rname += "arr";
    if (tif.find("(__fastcall *)") >= 0):
        rname = rname + "fn_" + str(n);
        return rname;
    if (tif.find("(__stdcall *)") >= 0):
        rname = rname + "fn_" + str(n);
        return rname;        
    if (tif.find("void (*)(") >= 0):
        rname = rname + "fn_" + str(n);
        return rname;        
    tif = tif.replace("*", "").replace("unsigned ","u").replace("struct ","").replace("int","i").replace("__int","i").replace("int64","i64").replace("__int64","i64").replace("_","").replace("[","").replace("]","").replace(" ","").lower();
    rname = rname + tif + "_" + str(n);
    return rname;

#lvar_t_newname("struct CLVDrawState *", 10);
#lvar_t_newname("CLVItemStore *", 10);
#lvar_t_newname("void (__fastcall *)(CListView *, __int64, HDC, __int64)", 10);
#lvar_t_newname("unsigned __int64", 10);
#lvar_t_newname("unsigned int", 10);
#lvar_t_newname("struct tagTRACKMOUSEEVENT", 10);
#lvar_t_newname("__int64", 10);
#lvar_t_newname("int", 10);
#lvar_t_newname("_QWORD", 10);
#lvar_t_newname("DWORD", 10);
#lvar_t_newname("__int64 (__fastcall *)(CListView *__hidden this, int, int, const unsigned __int16 *)",10);

def run():

    cfunc = idaapi.decompile(idaapi.get_screen_ea())
    if not cfunc:
        print 'Please move the cursor into a function.'
        return

    entry_ea = cfunc.entry_ea
    print "Dump of user-defined information for function at %x" % (entry_ea, )
    #print cfunc;

    # Display user defined labels.
    # labels = ida_hexrays.restore_user_labels(entry_ea);
    labels = cfunc.get_lvars();

    if labels is not None:
        for i in range(labels.capacity()):
            label = labels.at(i);
            if (is_default_lvar_t(label.name)):
                print "Renaming to ", lvar_t_newname(str(label.tif),i), " ", (label.name), " ", (label.tif);
                newname = lvar_t_newname(str(label.tif),i);
                label.name = newname;
                label.set_user_name();
            #else:
            #    print "Label ", (label.name), " ", (label.tif);

        cfunc.build_c_tree();
        cfunc.save_user_labels();
    return


if idaapi.init_hexrays_plugin():
    run()
else:
    print 'dump user info: hexrays is not available.'
