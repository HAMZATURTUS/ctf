# MetaCTF25 - Maydaymayday

category: rev eng

difficulty: Medium

## Source

```bash
> ls
maydaymayday
> file maydaymayday
maydaymayday: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3c8e8f8b7c29db438dfc74bdc329dc28a994dca2, for GNU/Linux 3.2.0, not stripped
```

[source](https://drive.google.com/file/d/14ccexIRgXaMcsuRRlIM-0H8w6avHxmic/view?usp=sharing)


Running maydaymayday:

```bash
> ./maydaymayday 
✈️ ═══════════════════════════════════════════════════════════ ✈️🚁
║                 AVIATION SECURITY SYSTEM                    ║
║              "Flight Control Access Terminal"              ║
║                                                             ║
║  🛩️  Unauthorized access to aircraft systems detected      ║
║  📡  Please provide valid pilot clearance code             ║
✈️ ═══════════════════════════════════════════════════════════ ✈️🚁

📡 Radar scanning \
🔍 Scanning for hostile aircraft...
⏱️  Analyzing flight patterns [██████████████████████████████] 100%
🎯 Enter pilot clearance code:
```

After a painfully long and boring process of text printing (and debugger detecting), the program asks for a "clearance code". A decompilation will reveal some more context:

```c
00401e48    int32_t main(int32_t argc, char** argv, char** envp)

00401e48    {
00401e48        animated_border();
00401e6c        typewriter_print(&data_403330, 0x1e);
00401e80        typewriter_print(&data_403378, 0x1e);
00401e94        typewriter_print(&data_4033c0, 0x1e);
00401ea8        typewriter_print(&data_403408, 0x1e);
00401ebc        typewriter_print(&data_403458, 0x1e); // "Enter pilot clearance code:"
00401ec6        animated_border();
00401ed0        putchar(0xa);
00401eda        spinning_radar(3);
00401eee        animated_dots(&data_4034a0, 3);
00401eee        
00401eff        if (radar_sweep())
00401eff        {
00401f42            blinking_alert("MAYDAY! MAYDAY! Enemy radar lock…", 3);
00401f24            typewriter_print(&data_4034f8, 0x32);
00401f2e            exit(1);
00401f2e            /* no return */
00401eff        }
00401eff        
00401f42        progress_bar(&data_403528, 0x5dc);
00401f42        
00401f53        if (check_flight_time())
00401f53        {
00401f96            blinking_alert("ALTITUDE WARNING: Abnormal fligh…", 3);
00401f78            typewriter_print(&data_403588, 0x32);
00401f82            exit(1);
00401f82            /* no return */
00401f53        }
00401f53        
00401f96        typewriter_print(&data_4035c0, 0x28);
00401fa5        fflush(__TMC_END__);
00401fc0        char buf[0x200];
00401fc0        fgets(&buf, 0x200, stdin);
00401fde        buf[strcspn(&buf, U"\n")] = 0;
00401feb        putchar(0xa);
00401fff        animated_dots(&data_4035e8, 4);
00402009        atc_system();
0040201d        animated_dots(&data_403610, 3);
00402052        double zmm0_1 =
00402052            calculate_bearing(40.712800000000001, -74.006, 51.507399999999997, -0.1278);
0040206f        typewriter_print(&data_403634, 0x28);
00402078        int512_t zmm0_2;
00402078        zmm0_2 = (uint128_t)zmm0_1;
0040208c        printf("%.2f degrees\n", zmm0_2);
004020a0        progress_bar(&data_403659, 0x7d0);
004020a0        
004020b6        if (!validate_flight_plan(&buf))
004020b6        {
00402196            putchar(0xa);
004021aa            blinking_alert("ACCESS DENIED - INVALID CLEARANC…", 2);
004021b9            puts(&data_4037c0);
004021cd            typewriter_print(&data_403840, 0x32);
004021e1            typewriter_print(&data_403870, 0x32);
004021f5            typewriter_print(&data_403898, 0x32);
00402204            puts(&data_4037c0);
0040220e            putchar(0xa);
00402222            animated_dots(&data_4038c8, 3);
0040222c            fake_transponder();
004020b6        }
004020b6        else
004020b6        {
004020c1            putchar(0xa);
004020c1            
004020f0            for (int32_t i = 0; i <= 2; i += 1)
004020f0            {
004020f0                puts(&data_403678);
004020e3                usleep(0x186a0);
004020f0            }
004020f0            
00402101            typewriter_print(&data_4036f8, 0x32); // "CLEARANCE GRANTED"
00402115            typewriter_print(&data_403728, 0x32);
00402129            typewriter_print(&data_403750, 0x32);
0040213d            typewriter_print(&data_403776, 0x32);
00402151            typewriter_print(&buf, 0x1e);
0040215b            putchar(0xa);
0040215b            
0040218a            for (int32_t i_1 = 0; i_1 <= 2; i_1 += 1)
0040218a            {
0040218a                puts(&data_403678);
0040217d                usleep(0x186a0);
0040218a            }
004020b6        }
004020b6        
00402237        return 0;
00401e48    }
```

The majority of these functions are not really relevant to the goal of finding the clearance code, such as typewriter print, which just prints text slowly, and functions like radar sweep, which aborts the program if a debugger is detected.

We are mostly concerned with the call of validate_flight_plan(), as it seems to be the deciding factor between printing "ACCESS DENIED" and "CLEARANCE GRANTED"

```c
00401a73    int64_t validate_flight_plan(char* arg1)

00401a73    {
00401a73        if (strlen(arg1) != 0x20)
00401a9b            return 0;
00401a9b        
00401b89        for (int32_t i = 0; i <= 0x1f; i += 1)
00401b89        {
00401b89            if ((arg1[(int64_t)i] <= 0x40 || arg1[(int64_t)i] > 0x5a)        // within A-Z
00401b89                    && (arg1[(int64_t)i] <= 0x60 || arg1[(int64_t)i] > 0x7a) // within a-z
00401b89                    && (arg1[(int64_t)i] <= 0x2f || arg1[(int64_t)i] > 0x39) // within 0-9
00401b89                    && arg1[(int64_t)i] != 0x7b && arg1[(int64_t)i] != 0x7d  // either '{' or '}'
00401b89                    && arg1[(int64_t)i] != 0x5f && arg1[(int64_t)i] != 0x2d) // either '-' or '_'
00401b77                return 0;
00401b89        }
00401b89        
00401c01        if (*(uint8_t*)arg1 != 0x4d || arg1[1] != 0x45 || arg1[2] != 0x54 || arg1[3] != 0x41
00401c01                || arg1[4] != 0x43 || arg1[5] != 0x54 || arg1[6] != 0x46
00401c01                || arg1[7] != 0x7b)
00401c1a            return 0;
00401c1a        
00401c1a        if (arg1[0x1f] != 0x7d)
00401c26            return 0;
00401c26        
00401c53        char var_38[0x17];
00401c53        
00401c53        for (int32_t i_1 = 0; i_1 <= 0x16; i_1 += 1)
00401c53            var_38[(int64_t)i_1] = arg1[(int64_t)i_1 + 8];
00401c53        
00401c55        char var_21_1 = 0;
00401c60        phonetic_decode(&var_38);
00401c76        aviation_decrypt(&var_38, 0x17, 0x17);
00401c8f        int64_t var_58;
00401c8f        __builtin_strncpy(&var_58, "#~&# &\'v:m#\" $r:t&n\' ::", 0x17);
00401ca5        int32_t var_14_1 = 0;
00401ca5        
00401cd5        while (true)
00401cd5        {
00401cd5            if (var_14_1 > 0x16)
00401cd7                return 1;
00401cd7            
00401cc4            if (var_38[(int64_t)var_14_1] != *(uint8_t*)(&var_58 + (int64_t)var_14_1))
00401cc4                break;
00401cc4            
00401ccd            var_14_1 += 1;
00401cd5        }
00401cd5        
00401cc6        return 0;
00401a73    }
```

