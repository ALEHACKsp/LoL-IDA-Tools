from idc import BADADDR, INF_BASEADDR, SEARCH_DOWN, FUNCATTR_START, FUNCATTR_END
import idc
import idaapi
import datetime

def DecToHex(Addr):
	return "0x%0.2X" % Addr

def MakeEnum(enumName, offsetArray):
    print ("enum class %s\r\n{" % enumName)
    for offset in offsetArray:
        if len(offset[0]) == 0:
            print ("")
            continue
        if type(offset[1]) is str:
            print ("   %s = %s," % ( offset[0], offset[1]))
            continue

        fncValue = offset[1] if offset[1] != -1 else 0x0

        locByName = idc.get_name_ea_simple(offset[0])
        isMismatch = locByName == 0x0

        if locByName == BADADDR:
            locByName = fncValue
        
        if locByName > idaapi.get_imagebase():
            set_name(locByName, offset[0])
            locByName = locByName - idaapi.get_imagebase()

        print ("   %s = %s,%s" % (offset[0], hex(locByName), '// Possible mismatch' if isMismatch else ''))

    print ("};\r\n")
    
def FindFunctionAddr(name, offset, operandValue):
    address = idc.find_binary(0, SEARCH_DOWN, "\"" + name + "\"")
    dword = -1
    
    if address == BADADDR:
        return BADADDR
	
    xrefs = XrefsTo(address)
    for xref in xrefs:
        dword = xref.frm + offset
    
    if dword == BADADDR:
        return BADADDR
    
    return idc.get_operand_value(dword, operandValue)

def FindOffsetPattern(Pattern, Operand):
	addr = idc.find_binary(0, SEARCH_DOWN, Pattern)
	if addr == BADADDR: return 0
	
	return idc.get_operand_value(addr, Operand)

def FindFunctionFirstXRef(name):
    address = idc.find_binary(0, SEARCH_DOWN, "\"" + name + "\"")
    dword = BADADDR
    
    if address == BADADDR:
        return BADADDR
    
    xrefs = XrefsTo(address)
    for xref in xrefs:
        dword = xref.frm
	
    try:
        return idaapi.get_func(dword).startEA
    except Exception:
        return -1

def FindFunctionByPatternStartEA(pattern):
    address = idc.find_binary(0, SEARCH_DOWN, pattern)
    if address == BADADDR:
        return BADADDR
	

    try:
        return idaapi.get_func(address).start_ea
    except Exception:
        return -1
        
def FindFuncCall(Pattern): # Find's Func. by Pattern to a Call
    addr = idc.find_binary(0, SEARCH_DOWN, Pattern)
    if addr == BADADDR: return 0
    return idc.get_operand_value(addr, 0)

def main():
    print ("[*] League of Legends Client Update Tool")
    print ("[*] By Dencelle for unknowncheats.me")
    print ("[*] Started at: %s" % datetime.datetime.now())
    print ("----------------------------")
    # Functions that need to be sorted
    MakeEnum("Functions", [
        ["GetNextObject", FindFunctionByPatternStartEA("8B 44 24 04 56 8B 71 18")],
        ["GameVersion", FindFuncCall("E8 ? ? ? ? 50 68 ? ? ? ? 6A 00 6A 01 6A 02 E8 ? ? ? ? E8 ? ? ? ?")],
        ["GetFirstObject", FindFuncCall("E8 ? ? ? ? 8B F0 85 F6 74 21 0F 1F 44 00 ?")],
        ["WorldToScreen", FindFunctionByPatternStartEA("83 EC 10 56 E8 ? ? ? ? 8B 08")],
        ["CastSpell", FindFunctionFirstXRef("ERROR: Client Tried to cast a spell from")],
        ["DrawCircle", FindFunctionByPatternStartEA("33 C4 89 84 24 ? ? ? ? F3 0F 10 84 24 ? ? ? ? 8D 0C")],
        ["GetBasicAttack", FindFunctionByPatternStartEA("53 8B D9 B8 ? ? ? ? 8B 93")],
        ["GetAttackCastDelay", FindFunctionByPatternStartEA("83 EC 0C 53 8B 5C 24 14 8B CB 56")],
        ["GetAttackDelay", FindFunctionByPatternStartEA("8B 44 24 04 51 F3")],
        ["GetPing", FindFunctionByPatternStartEA("55 8B EC 83 EC 08 0F B6")],
        ["GetSpellState", FindFuncCall("E8 ? ? ? ? 8B F8 8B CB 89")],
        ["IsTargetable", FindFunctionByPatternStartEA("56 8B F1 E8 ? ? ? ? 84 C0 74 2E 8D")],
        ["IsAlive", FindFunctionByPatternStartEA("56 8B F1 8B 06 8B 80 ? ? ? ? FF D0 84 C0 74 19")],
        ["IsBaron", FindFunctionByPatternStartEA("56 81 C1 ? ? ? ? E8 ? ? ? ? 68")],
        ["IsTurret", FindFuncCall("E8 ? ? ? ? 83 C4 04 84 C0 75 ?")],
        ["IsInhib", FindFuncCall("E8 ? ? ? ? 55 88 44 24 1F")],
        ["IsHero", FindFuncCall("E8 ? ? ? ? 83 C4 04 84 C0 74 52")],
        ["IsMinion", FindFuncCall("E8 ? ? ? ? 83 C4 04 80 7F 26 06")],
        ["IsDragon", FindFunctionByPatternStartEA("83 EC 10 A1 ? ? ? ? 33 C4 89 44 24 0C 56 81")],
        ["IsMissile", FindFuncCall("E8 ? ? ? ? 83 C4 04 84 C0 74 3F")],
        ["IsNexus", FindFuncCall("E8 ? ? ? ? 55 88 44 24 20")],
        ["IsNotWall", FindFunctionByPatternStartEA("85 FF 0F 48 C3 0F AF C8 8B 86 ? ? ? ? 5F 5E 5B 03 CA 8D")],
        ["IsTroy", FindFuncCall("E8 ? ? ? ? 33 C9 83 C4 04 84 C0 0F 45 4C 24 ? 8B C1 C3 CC CC CC CC CC CC CC CC FF 74 24 04 E8 ? ? ? ? 33 C9 83 C4 04 84 C0 0F 45 4C 24 ? 8B C1 C3 CC CC CC CC CC CC CC CC 56")],
        ["IssueOrder", FindFuncCall("E8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B 84 ?? ?? ?? ?? ?? 8B CF F3 0F 7E 00")],
        ["PrintChat", FindFuncCall("E8 ? ? ? ? 8B 77 40 8A 47 48")],
        ["SendChat", FindFunctionByPatternStartEA("A1 ? ? ? ? 56 6A FF")],
        ["GetTimerExpiry", FindFuncCall("E8 ? ? ? ? 51 D9 1C 24 E8 ? ? ? ? 8B")],
        ["HealthBarPosition", FindFuncCall("E8 ?? ?? ?? ?? 8B 4E ?? 8D 54 ?? ?? 52 8B 01 FF ?? ?? 5E 83 ?? ?? C3")],
        ["BaseDrawPosition", FindFunctionByPatternStartEA("30 44 14 10 42 3B D1 72 F0 8B 74 24 14 83 7C 24 ? ? 74")],
        ["Hud_OnDisconnect", FindFunctionFirstXRef("game_messagebox_caption_disconnect")],
        ["Hud_OnAfk", FindFunctionFirstXRef("game_messagebox_text_afkwarningcaption")],
        ["OnCreateObject", FindFuncCall("E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 ?? 32 C9 EB")],
        ["oOnDeleteObject", FindFuncCall("E8 ? ? ? ? 8B 4E 20 85 C9 74 0F")],
        ["translateString_UNSAFE_DONOTUSE", FindFuncCall("E8 ? ? ? ? 8B 0D ? ? ? ? 83 C4 04 8B F0 6A 0B")],
        ["CharacterDataStack__Push", FindFunctionByPatternStartEA("83 EC 4C 53 57")],
        ["CharacterDataStack__Update", FindFunctionByPatternStartEA("83 EC 18 53 56 57 8D 44 24 20")],
        ["GetOwnerObject", FindFuncCall("E8 ? ? ? ? 39 44 24 1C 5F")],
        ["CharacterData__GetCharacterPackage", FindFunctionByPatternStartEA("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 56 8B B4 24 ? ? ? ? 8B C6")],
        ["GetAiManager", FindFuncCall("E8 ?? ?? ?? ?? 50 8B CE E8 ?? ?? ?? ?? 80 BB ?? ?? ?? ?? ??")],
        ["SetBaseCharacterData", FindFuncCall("E8 ?? ?? ?? ?? 8B 54 ?? ?? 83 ?? ?? 72 ?? 8B 4C ?? ?? 42 8B C1 81 ?? ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 ?? ?? 2B C1 83 ?? ?? 83 ?? ?? 0F ?? ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 ?? ?? 8B 06 8B CE FF ?? ?? ?? ?? ?? 8B CE F3 0F")],
        ["OnprocessSpell", FindFuncCall("E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 80 BE ?? ?? ?? ?? ?? D8")],
        ["OnNewPath", FindFunctionByPatternStartEA("83 EC 18 56 8B 74 24 20 8B CE 57")],
        ["Riot__Renderer__MaterialRegistry__GetSingletonPtr", FindFunctionByPatternStartEA("A1 ? ? ? ? 85 C0 75 0B 8B 0D ? ? ? ? 8B 01 FF 60 14")],
        ["GetGoldRedirectTarget", FindFuncCall("E8 ? ? ? ? 39 44 24 1C 5F")],
        ["SummonerEmoteUserComponent__GetSummonerEmoteData", FindFunctionByPatternStartEA("81 EC ? ? ? ? A1 ? ? ? ? 33 C4 89 84 24 ? ? ? ? 56 FF B4 24 ? ? ? ? 8D 44 24 14")],
        ["SummonerEmoteUserComponent__SetEmoteIdForSlot", FindFunctionByPatternStartEA("83 EC 08 56 57 FF 74 24 14")],
    ])
    # Offsets that need to be sorted
    MakeEnum("Offsets", [
        ["RetAddr", idc.find_binary(0, SEARCH_DOWN, "E8 ? ? ? ? 83 C4 1C C3 E8 ? ? ? ?")+0x8],
        ["DrawCircleRetAddr", idc.find_binary(0, SEARCH_DOWN, "83 C4 1C C3")],
        ["NetClient", FindOffsetPattern("8B 0D ? ? ? ? 85 C9 74 07 8B 01 6A 01 FF 50 08 8B", 1)],
        ["PingInstance", FindOffsetPattern("8B 0D ? ? ? ? 85 C9 74 07 8B 01 6A 01 FF 50 08 8B", 1)],
        ["ChatClientPtr", FindOffsetPattern("8B 35 ? ? ? ? 8D 44 24 14 53 8B 1D ? ? ? ? 8B CF", 1)],
        ["ObjManager", FindOffsetPattern("8B 0D ? ? ? ? 89 74 24 14", 1)],
        ["ZoomClass", FindOffsetPattern("A3 ? ? ? ? 83 FA 10 72 32", 0)],
        ["GameInfo", FindOffsetPattern("A1 ? ? ? ? 83 78 08 02 0F 94", 1)],
        ["HudInstance", FindOffsetPattern("8B 0D ? ? ? ? 6A 00 8B 49 34 E8 ? ? ? ? B0 01 C2", 1)],
        ["Renderer", FindOffsetPattern("8B 15 ? ? ? ? 83 EC 08", 1)],
        ["UnderMouseObject", FindOffsetPattern("8B 0D ? ? ? ? 89 0D", 1)],
        ["D3DRenderer", FindOffsetPattern("A1 ? ? ? ? 68 ? ? ? ? 8B 70 08 E8", 1)],
        ["LocalPlayer", FindOffsetPattern("A1 ?? ?? ?? ?? 85 C0 74 07 05 ?? ?? ?? ?? EB 02 33 C0 56", 1)],
        ["GameTime", FindOffsetPattern("F3 0F 11 05 ? ? ? ? 8B 49", 0)],
        ["MenuGUI", FindOffsetPattern("8B 0D ? ? ? ? 6A 00 E8 ? ? ? ? C7", 1)],
        ["ChampionManager", FindOffsetPattern("89 1D ?? ?? ?? ?? 56 8D 4B 04", 0)],
        ["ManagerTemplate_AIMinionClient_", FindOffsetPattern("A1 ?? ?? ?? ?? 53 55 8B 6C 24 1C", 1)],
        ["ManagerTemplate_AIHero_", FindOffsetPattern("8B 0D ?? ?? ?? ?? 50 8D 44 24 18", 1)],
        ["IsLaneMinion", FindOffsetPattern("8A 87 ? ? ? ? 88 4C 24 0B", 1)-1],
        ["CharacterDataStack", FindOffsetPattern("8D 8E ? ? ? ? 89 44 24 28 C7 44 24 ? ? ? ? ? C6 44 24 ? ? E8 ? ? ? ? FF 30 8D 44 24 2C 68 ? ? ? ?", 1)],
        ["SkinId", FindOffsetPattern("80 BF ? ? ? ? ? 75 50 0F 31 33 C9 66 C7 87 ? ? ? ? ? ?", 0)],
        ["Riot__g_window", FindOffsetPattern("3B 05 ? ? ? ? 75 72", 1)],
        ["GfxWinMsgProc", FindOffsetPattern("A1 ? ? ? ? 55 57 53", 1)],
        ["GameClient", FindOffsetPattern("A1 ? ? ? ? 68 ? ? ? ? 8B 70 08", 1)],
        ["D3DDevice", FindOffsetPattern("8B 86 ? ? ? ? 89 4C 24 08", 1)],
        ["SwapChain", FindOffsetPattern("8B 8E ? ? ? ? 52 57", 1)],
        ["oObjPerk1", FindOffsetPattern("8D 8E ? ? ? ? E8 ? ? ? ? 8B CE E8 ? ? ? ? A1", 1)],
	])
    
main()