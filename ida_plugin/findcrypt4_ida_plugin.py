# -*- coding: utf-8 -*-

# import idaapi
import ida_idaapi
import idautils
import ida_bytes
import ida_kernwin
import ida_segment
import ida_nalt
import ida_name

import findcrypt4


class Kp_Menu_Context(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return ida_kernwin.register_action(ida_kernwin.action_desc_t(
            self.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        ida_kernwin.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        # dummy method
        return 1

    @classmethod
    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class Searcher(Kp_Menu_Context):
    def activate(self, ctx):
        self.plugin.search()
        return 1


class YaraSearchResultChooser(ida_kernwin.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["Address", ida_kernwin.Choose.CHCOL_HEX | 10],
                ["Rules file", ida_kernwin.Choose.CHCOL_PLAIN | 12],
                ["Name", ida_kernwin.Choose.CHCOL_PLAIN | 25],
                ["String", ida_kernwin.Choose.CHCOL_PLAIN | 25],
                ["Value", ida_kernwin.Choose.CHCOL_PLAIN | 40],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        ida_kernwin.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [ida_kernwin.ea2str(res[0]), res[1], res[2], res[3], res[4]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class FindcryptPlugin(ida_idaapi.plugin_t):
    comment = "Findcrypt plugin for IDA Pro (using yara framework)"
    help = "todo"
    wanted_name = "Findcrypt4"
    wanted_hotkey = "Ctrl-Alt-F"
    flags = ida_idaapi.PLUGIN_KEEP

    def init(self):
        self.current_values = None  # keep the current values (to enable retrieving them through scripting)

        # register popup menu handlers
        Searcher.register(self, "Findcrypt")

        ida_kernwin.register_action(ida_kernwin.action_desc_t(
            "Findcrypt",
            "Find crypto constants",
            Searcher(),
            None,
            None,
            0))
        ida_kernwin.attach_action_to_menu("Search", "Findcrypt", ida_kernwin.SETMENU_APP)
        print("=" * 80)
        print(f"Findcrypt v{findcrypt4.__version__} by Robin David 2024")
        print("Forked from Findcrypt v0.2 by David BERARD, 2017")
        print("Findcrypt search shortcut key is Ctrl-Alt-F")
        print("=" * 80)

        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        pass


    def search(self):
        print(">>> start yara search")
        # reset current values
        self.current_values = []

        for seg_addr in idautils.Segments():
            seg = ida_segment.getseg(seg_addr)
            content = ida_bytes.get_bytes(seg_addr, seg.end_ea - seg_addr)
            print(f"content len: {len(content)}")
            self.current_values.extend(self.yarasearch(content, seg_addr))

        print("<<< end yara search")
        c = YaraSearchResultChooser("Findcrypt results", self.current_values)
        c.show()

    def yarasearch(self, memory, base_addr):
        values = list()
        for match in findcrypt4.search(memory):
            print("match!")
            addr = base_addr + match.offset
            if match.rule.endswith("_API"):
                try:
                    match.rule = match.rule + "_" + ida_bytes.get_strlit_contents(addr, -1, ida_nalt.STRTYPE_C)
                except:
                    pass

            value = [
                addr,
                match.namespace,
                match.rule + "_" + hex(addr).lstrip("0x").rstrip("L").upper(),
                match.identifier,
                repr(match.data),
            ]
            ida_name.set_name(value[0], value[2], 0)
            values.append(value)
        print("values:", len(values))
        return values

    def run(self, arg):
        self.search()


plugin = None


# register IDA plugin
def PLUGIN_ENTRY():
    global plugin
    if plugin is None:
        plugin = FindcryptPlugin()
    return plugin
