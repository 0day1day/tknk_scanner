import os

ignore = ["general_cloaking.yar", "yara_mixed_ext_vars.yar", "generic_anomalies.yar", "thor_inverse_matches.yar", "MALW_Httpsd_ELF.yar", "MALW_AZORULT.yar","MALW_Torte_ELF.yar", "MALW_Mirai_Okiru_ELF.yar", "MALW_Mirai_Satori_ELF.yar", "MALW_TinyShell_Backdoor_gen.yar", "RAT_CrossRAT.yar", "MALW_Rebirth_Vulcan_ELF.yar"]

duplicated = ["APT_Poseidon_Group.yar", "APT_OPCleaver.yar", "APT_FiveEyes.yar", "TOOLKIT_PassTheHash.yar", "APT_Turla_RUAG.yar", "MALW_TRITON_ICS_FRAMEWORK.yar", "RAT_DarkComet.yar", "APT_fancybear_dnc.yar", "POS_MalumPOS.yar", "MALW_FakeM.yar", "APT_Backspace.yar", "APT_Ke3Chang_TidePool.yar", "APT_Greenbug.yar", "APT_WildNeutron.yar", "RAT_PoisonIvy.yar", "RANSOM_Locky.yar", "MALW_Lenovo_Superfish.yar", "POS_Bernhard.yar", "MALW_Naikon.yar", "APT_Snowglobe_Babar.yar", "APT_Irontiger.yar", "RAT_Ratdecoders.yar", "APT_ThreatGroup3390.yar", "TOOLKIT_THOR_HackTools.yar", "MALW_Buzus_Softpulse.yar", "RAT_Adwind.yar", "APT_DPRK_ROKRAT.yar", "MALW_Kraken.yar", "APT_Regin.yar", "RANSOM_MS17-010_Wannacrypt.yar", "APT_Unit78020.yar", "TOOLKIT_Chinese_Hacktools.yar", "APT_Duqu2.yar", "APT_APT29_Grizzly_Steppe.yar", "MALW_xDedic_marketplace.yar", "APT_EQUATIONGRP.yar", "APT_Oilrig.yar", "APT_Grizzlybear_uscert.yar", "MALW_Enfal.yar", "POS.yar", "TOOLKIT_exe2hex_payload.yar", "APT_WoolenGoldfish.yar", "APT_furtim.yar", "APT_Cloudduke.yar", "MALW_BackdoorSSH.yar", "APT_Passcv.yar", "APT_Industroyer.yar", "APT_Stuxnet.yar", "APT_APT17.yar", "MALW_Skeleton.yar", "APT_Blackenergy.yar", "APT_Sofacy_Fysbis.yar", "APT_CrashOverride.yar", "APT_APT10.yar", "MALW_Empire.yar", "APT_Sofacy_Bundestag.yar", "MALW_Fareit.yar", "MALW_KINS.yar", "APT_Shamoon_StoneDrill.yar", "APT_CheshireCat.yar", "APT_APT15.yar", "RAT_Nanocore.yar", "TOOLKIT_Pwdump.yar", "APT_Platinum.yar", "APT_Platinum.yar", "MALW_Dexter.yar", "MALW_Upatre.yar", "APT_UP007_SLServer.yar", "APT_Hellsing.yar", "MALW_Shamoon.yar", "APT_Emissary.yar", "APT_RemSec.yar", "APT_FVEY_ShadowBrokers_Jan17_Screen_Strings.yar", "APT_Dubnium.yar", "APT_Equation.yar", "APT_Waterbug.yar", "APT_Sofacy_Jun16.yar", "MALW_Exploit_UAC_Elevators.yar", "RANSOM_Cryptolocker.yar", "APT_Minidionis.yar", "MALW_Korplug.yar", "APT_HackingTeam.yar", "APT_HiddenCobra.yar", "APT_Winnti.yar", "APT_Sphinx_Moth.yar", "APT_Terracota.yar", "MALW_TRITON_HATMAN.yar", "APT_eqgrp_apr17.yar", "TOOLKIT_Gen_powerkatz.yar", "APT_Casper.yar", "MALW_Miscelanea.yar", "RAT_Shim.yar", "RAT_Indetectables.yar", "RANSOM_GoldenEye.yar", "APT_Prikormka.yar", "APT_Derusbi.yar", "RAT_Inocnation.yar", "APT_PutterPanda.yar", "APT_Codoso.yar", "APT_Bluetermite_Emdivi.yar", "APT_Seaduke.yar", "MALW_Corkow.yar"]

cape_diplicated=["Arkei.yar", "Adzok.yar", "T5000.yar", "CyberGate.yar", "ShadowTech.yar", "xRAT.yar", "Kovter.yar", "Xtreme.yar", "BlackShades.yar", "Bozok.yar", "NetTraveler.yar"]

no_use = ["MALW_CAP_Win32Inet.yara", "MALW_LURK0.yar", "MALW_Surtr.yar", "RAT_Bolonyokte.yar", "MALW_Glasses.yar", "MALW_IcedID.yar", "MALW_Miancha.yar"]

def find_signatures(root):
        signatures = []
        for entry in os.listdir(root):
            if (entry.endswith(".yara") or entry.endswith(".yar")) and (entry not in ignore) and (entry not in duplicated) and (entry not in no_use) and (entry not in cape_diplicated):
                signatures.append(os.path.join(root, entry))

        return signatures

if __name__ == "__main__":
        generated = []
        paths = ["yara/my_rules","yara/Neo23x0", "yara/rules/malware", "yara/CAPE"]
        
        for path in paths:
            generated.extend(find_signatures(path))
        
        #print(generated)

        # Create index file and populate it.
        with open("index.yar", "w") as index_handle:
            for signature in generated:
                index_handle.write("include \"./{0}\"\n".format(signature))
