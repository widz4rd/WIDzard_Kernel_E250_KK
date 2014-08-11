/*
 * Author: andip71, 10.02.2014
 * 
 * Modifications: Yank555.lu 20.08.2013
 *
 * Version 1.6.6
 *
 * credits: Supercurio for ideas and partially code from his Voodoo
 * 	    	sound implementation,
 *          Yank555 for great support on problem analysis and new ideas,
 *          Gokhanmoral for further modifications to the original code
 * 			AndreiLux for his modified detection routines
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/*
 * Change log:
 * 
 * 1.6.5 (14.01.2014)
 *   - Allow speaker level minimum of 20
 * 
 */

#include <sound/soc.h>
#include <sound/core.h>
#include <sound/jack.h>

#include <linux/miscdevice.h>
#include <linux/mfd/wm8994/core.h>
#include <linux/mfd/wm8994/registers.h>
#include <linux/mfd/wm8994/pdata.h>
#include <linux/mfd/wm8994/gpio.h>

#include "wm8994.h"

#include "boeffla_sound.h"

// Use delayed work to re-apply eq on headphone changes
#include <linux/jiffies.h>
#include <linux/workqueue.h>

struct delayed_work apply_settings_work;
bool apply_settings_work_scheduled = false;
int change_delay = DEFAULT_CHANGE_DELAY;

/*****************************************/
// Static variables
/*****************************************/

// pointer to codec structure
static struct snd_soc_codec *codec;
static struct wm8994_priv *wm8994;

// internal boeffla sound variables
static int boeffla_sound;		// boeffla sound master switch
static int debug_level;			// debug level for logging into kernel log

static int headphone_l, headphone_r;	// headphone volume left/right

static int speaker_l, speaker_r;		// speaker volume left/right

static int speaker_tuning;  	// activates speaker eq

static int eq;   				// activates headphone eq

static int eq_gains[5];			// gain information for headphone eq (speaker is static)

static unsigned int eq_bands[5][4];	// frequency setup for headphone eq (speaker is static)

static int dac_direct;			// activate dac_direct for headphone eq
static int dac_oversampling;	// activate 128bit oversampling for headphone eq
static int fll_tuning;			// activate fll tuning to avoid jitter
static int stereo_expansion_gain;	// activate stereo expansion effect if greater than zero
static int mono_downmix;		// activate mono downmix
static int privacy_mode;		// activate privacy mode

static int mic_level_general;	// microphone sensivity for general recording purposes
static int mic_level_call;		// microphone sensivity for call only

static unsigned int debug_register;		// current register to show in debug register interface

// internal state variables
static bool is_call;			// is currently a call active?
static bool is_headphone;		// is headphone connected?
static bool is_fmradio;			// is stock fm radio app active?
static bool is_eq;				// is an equalizer (headphone or speaker tuning) active?
static bool is_eq_headphone;	// is equalizer for headphone or speaker currently?
static bool is_mic_controlled;	// is microphone sensivity controlled by boeffla-sound or not?
static bool is_mono_downmix;	// is mono downmix active?

static int regdump_bank;		// current bank configured for register dump
static unsigned int regcache[REGDUMP_BANKS * REGDUMP_REGISTERS + 1];	// register cache to highlight changes in dump

static int mic_level;			// internal mic level


/*****************************************/
// Internal function declarations
/*****************************************/

static unsigned int wm8994_read(struct snd_soc_codec *codec, unsigned int reg);
static int wm8994_write(struct snd_soc_codec *codec, unsigned int reg, unsigned int value);

static bool debug(int level);
static bool check_for_call(void);
static bool check_for_headphone(void);
static bool check_for_fmradio(void);

// Modified by WIDzard Str@wberry
static void set_headphone_l(void);
static void set_headphone_r(void);
static unsigned int get_headphone_l(unsigned int val);
static unsigned int get_headphone_r(unsigned int val);
// Modified by WIDzard Str@wberry
static void set_speaker_l(void);
static void set_speaker_r(void);
static unsigned int get_speaker_l(unsigned int val);
static unsigned int get_speaker_r(unsigned int val);

static void set_eq(void);
static void set_eq_gains(void);
static void set_eq_bands(void);
static void set_eq_satprevention(void);
static unsigned int get_eq_satprevention(int reg_index, unsigned int val);
static void set_speaker_boost(void);

static void set_dac_direct(void);
static unsigned int get_dac_direct_l(unsigned int val);
static unsigned int get_dac_direct_r(unsigned int val);

static void set_dac_oversampling(void);
static void set_fll_tuning(void);
static void set_stereo_expansion(void);
static void set_mono_downmix(void);
static unsigned int get_mono_downmix(unsigned int val);

static void set_mic_level(void);
static unsigned int get_mic_level(int reg_index, unsigned int val);

static void reset_boeffla_sound(void);


/*****************************************/
// Boeffla sound hook functions for
// original wm8994 alsa driver
/*****************************************/

void Boeffla_sound_hook_wm8994_pcm_probe(struct snd_soc_codec *codec_pointer)
{
	// store a copy of the pointer to the codec, we need
	// that for internal calls to the audio hub
	codec = codec_pointer;

	// store pointer to codecs driver data
	wm8994 = snd_soc_codec_get_drvdata(codec);

	// Print debug info
	printk("Boeffla-sound: codec pointer received\n");

	// Initialize boeffla sound master switch finally
	boeffla_sound = BOEFFLA_SOUND_DEFAULT;

	// If boeffla sound is enabled during driver start, reset to default configuration
	if (boeffla_sound == ON)
	{
		reset_boeffla_sound();
		printk("Boeffla-sound: boeffla sound enabled during startup\n");
	}
}


unsigned int Boeffla_sound_hook_wm8994_write(unsigned int reg, unsigned int val)
{
	unsigned int newval;
	bool change_regs = false;

	bool current_is_call;
	bool current_is_headphone;
	bool current_is_fmradio;

	// Terminate instantly if boeffla sound is not enabled and return
	// original value back
	if (!boeffla_sound)
		return val;

	// Detect current output for call, headphone and fm radio
	current_is_call	= check_for_call();
	current_is_headphone = check_for_headphone();
	current_is_fmradio = check_for_fmradio();

	// If the write request of the original driver is for specific registers,
	// change value to boeffla sound values accordingly as new return value
	newval = val;

	// based on the register, do the appropriate processing
	switch (reg)
	{

		// left headphone volume
		case WM8994_LEFT_OUTPUT_VOLUME:
		{
			newval = get_headphone_l(val);
			break;
		}

		// right headphone volume
		case WM8994_RIGHT_OUTPUT_VOLUME:
		{
			newval = get_headphone_r(val);
			break;
		}

		// left speaker volume
		case WM8994_SPEAKER_VOLUME_LEFT:
		{
			newval = get_speaker_l(val);
			break;
		}

		// right speaker volume
		case WM8994_SPEAKER_VOLUME_RIGHT:
		{
			newval = get_speaker_r(val);
			break;
		}

// Do not touch dac direct at all when P4NOTE
#ifndef CONFIG_MACH_P4NOTE
		// dac_direct left channel
		case WM8994_OUTPUT_MIXER_1:
		{
			newval = get_dac_direct_l(val);
			break;
		}

		// dac_direct right channel
		case WM8994_OUTPUT_MIXER_2:
		{
			newval = get_dac_direct_r(val);
			break;
		}
#endif

		// mono downmix
		case WM8994_AIF1_DAC1_FILTERS_1:
		{
			newval = get_mono_downmix(val);
			break;
		}

		// EQ saturation prevention: dynamic range control 1_1
		case WM8994_AIF1_DRC1_1:
		{
			newval = get_eq_satprevention(1, val);
			break;
		}

		// EQ saturation prevention: dynamic range control 1_2
		case WM8994_AIF1_DRC1_2:
		{
			newval = get_eq_satprevention(2, val);
			break;
		}

		// EQ saturation prevention: dynamic range control 1_3
		case WM8994_AIF1_DRC1_3:
		{
			newval = get_eq_satprevention(3, val);
			break;
		}

		// EQ saturation prevention: dynamic range control 1_4
		case WM8994_AIF1_DRC1_4:
		{
			newval = get_eq_satprevention(4, val);
			break;
		}

		// Microphone: left input level
		case WM8994_LEFT_LINE_INPUT_1_2_VOLUME:
		{
			newval = get_mic_level(1, val);
			break;
		}

		// Microphone: right input level
		case WM8994_RIGHT_LINE_INPUT_1_2_VOLUME:
		{
			newval = get_mic_level(2, val);
			break;
		}

	}

	// Headphone detection
	if (is_headphone != current_is_headphone)
	{
		is_headphone = current_is_headphone;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: Output new status - %s\n", is_headphone ? "Headphone" : "Speaker");

		// Registers have to be updated
		change_regs = true;
	}

	// call detection
	if (is_call != current_is_call)
	{
		is_call = current_is_call;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: Call detection new status - %s\n", is_call ? "in call" : "not in call");

		// Registers have to be updated
		change_regs = true;
	}

	// FM radio detection
	if (is_fmradio != current_is_fmradio)
	{
		is_fmradio = current_is_fmradio;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: FM radio detection new status - %s\n", is_fmradio ? "active" : "inactive");

		// Registers have to be updated
		change_regs = true;
	}

	// Update sound environment due to change detection
	if (change_regs || is_headphone)
	{
		// New changes while work is still pending, cancel before rescheduling,
		// best is to set everything once all calls are through
		if (apply_settings_work_scheduled)
			cancel_delayed_work_sync(&apply_settings_work);

		// schedule to apply new settings in change_delay time
		schedule_delayed_work(&apply_settings_work, usecs_to_jiffies(change_delay));
		apply_settings_work_scheduled = true;
	}

	// print debug info
	if (debug(DEBUG_VERBOSE))
		printk("Boeffla-sound: write hook %d -> %d (Orig:%d), c:%d, h:%d, r:%d\n",
				reg, newval, val, is_call, is_headphone, is_fmradio);

	return newval;
}


/*****************************************/
// Internal functions copied over from
// original wm8994 alsa driver,
// enriched by some debug prints
/*****************************************/

static int wm8994_readable(struct snd_soc_codec *codec, unsigned int reg)
{
	//struct wm8994_priv *wm8994 = snd_soc_codec_get_drvdata(codec);
	struct wm8994 *control = codec->control_data;

	switch (reg) {
	case WM8994_GPIO_1:
	case WM8994_GPIO_2:
	case WM8994_GPIO_3:
	case WM8994_GPIO_4:
	case WM8994_GPIO_5:
	case WM8994_GPIO_6:
	case WM8994_GPIO_7:
	case WM8994_GPIO_8:
	case WM8994_GPIO_9:
	case WM8994_GPIO_10:
	case WM8994_GPIO_11:
	case WM8994_INTERRUPT_STATUS_1:
	case WM8994_INTERRUPT_STATUS_2:
	case WM8994_INTERRUPT_STATUS_1_MASK:
	case WM8994_INTERRUPT_STATUS_2_MASK:
	case WM8994_INTERRUPT_RAW_STATUS_2:
		return 1;

	case WM8958_DSP2_PROGRAM:
	case WM8958_DSP2_CONFIG:
	case WM8958_DSP2_EXECCONTROL:
		if (control->type == WM8958)
			return 1;
		else
			return 0;

	default:
		break;
	}

	if (reg >= WM8994_CACHE_SIZE)
		return 0;
	return wm8994_access_masks[reg].readable != 0;
}


static int wm8994_volatile(struct snd_soc_codec *codec, unsigned int reg)
{
	if (reg >= WM8994_CACHE_SIZE)
		return 1;

	switch (reg) {
	case WM8994_SOFTWARE_RESET:
	case WM8994_CHIP_REVISION:
	case WM8994_DC_SERVO_1:
	case WM8994_DC_SERVO_READBACK:
	case WM8994_RATE_STATUS:
	case WM8994_LDO_1:
	case WM8994_LDO_2:
	case WM8958_DSP2_EXECCONTROL:
	case WM8958_MIC_DETECT_3:
	case WM8994_DC_SERVO_4E:
		return 1;
	default:
		return 0;
	}
}


static int wm8994_write(struct snd_soc_codec *codec, unsigned int reg,
	unsigned int value)
{
	int ret;

	BUG_ON(reg > WM8994_MAX_REGISTER);

	if (!wm8994_volatile(codec, reg)) {
		ret = snd_soc_cache_write(codec, reg, value);
		if (ret != 0)
			dev_err(codec->dev, "Cache write to %x failed: %d",
				reg, ret);
	}

	// print debug info
	if (debug(DEBUG_VERBOSE))
		printk("Boeffla-sound: write register %d -> %d\n", reg, value);

	return wm8994_reg_write(codec->control_data, reg, value);
}


static unsigned int wm8994_read(struct snd_soc_codec *codec,
				unsigned int reg)
{
	unsigned int val;
	int ret;

	BUG_ON(reg > WM8994_MAX_REGISTER);

	if (!wm8994_volatile(codec, reg) && wm8994_readable(codec, reg) &&
	    reg < codec->driver->reg_cache_size) {
		ret = snd_soc_cache_read(codec, reg, &val);
		if (ret >= 0)
		{
			// print debug info
			if (debug(DEBUG_VERBOSE))
				printk("Boeffla-sound: read register from cache %d -> %d\n", reg, val);

			return val;
		}
		else
			dev_err(codec->dev, "Cache read from %x failed: %d",
				reg, ret);
	}

	val = wm8994_reg_read(codec->control_data, reg);

	// print debug info
	if (debug(DEBUG_VERBOSE))
		printk("Boeffla-sound: read register %d -> %d\n", reg, val);

	return val;
}


/*****************************************/
// Internal helper functions
/*****************************************/

bool check_for_dapm(enum snd_soc_dapm_type dapm_type, char* widget_name)
{
	struct snd_soc_dapm_widget *w;

	/* Iterate widget list and find power mode of given widget per its name */
	list_for_each_entry(w, &codec->card->widgets, list) 
	{
		if (w->dapm != &codec->dapm)
			continue;

		/* DAPM types in include/sound/soc-dapm.h */
		if (w->id == dapm_type && !strcmp(w->name, widget_name))
			return w->power;
	}

	return false;
}


bool check_for_fmradio(void)
{
// if no fm radio built in, always set to false
#ifdef CONFIG_FM_RADIO
	return check_for_dapm(snd_soc_dapm_line, "FM In");
#else
	return false;
#endif
}


bool check_for_call(void)
{
	return check_for_dapm(snd_soc_dapm_spk, "RCV");
}


bool check_for_headphone(void)
{
// different headphone detection for s3 devices and note devices
#ifndef CONFIG_MACH_P4NOTE
	if( wm8994->micdet[0].jack != NULL )
	{
		if ((wm8994->micdet[0].jack->status & SND_JACK_HEADPHONE) ||
		(wm8994->micdet[0].jack->status & SND_JACK_HEADSET))
			return true;
	}

	return false;
#else
	return check_for_dapm(snd_soc_dapm_hp, "HP");
#endif
}


static bool debug (int level)
{
	// determine whether a debug information should be printed according to currently
	// configured debug level, or not
	if (level <= debug_level)
		return true;

	return false;
}


/*****************************************/
// Internal set/get/restore functions
/*****************************************/


// Headphone volume
// Modified by WIDzard Str@wberry
static void set_headphone_l(void)
{
	unsigned int val;

	// get current register value, unmask volume bits, merge with boeffla sound volume and write back
	val = wm8994_read(codec, WM8994_LEFT_OUTPUT_VOLUME);
	val = (val & ~WM8994_HPOUT1L_VOL_MASK) | headphone_l;
        wm8994_write(codec, WM8994_LEFT_OUTPUT_VOLUME, val);

}
// Headphone volume
// Modified by WIDzard Str@wberry
static void set_headphone_r(void)
{
	unsigned int val;

	val = wm8994_read(codec, WM8994_RIGHT_OUTPUT_VOLUME);
	val = (val & ~WM8994_HPOUT1R_VOL_MASK) | headphone_r;
        wm8994_write(codec, WM8994_RIGHT_OUTPUT_VOLUME, val | WM8994_HPOUT1_VU);

}
static unsigned int get_headphone_l(unsigned int val)
{
	// return register value for left headphone volume back
        return (val & ~WM8994_HPOUT1L_VOL_MASK) | headphone_l;
}


static unsigned int get_headphone_r(unsigned int val)
{
	// return register value for right headphone volume back
        return (val & ~WM8994_HPOUT1R_VOL_MASK) | headphone_r;
}


// Speaker volume
// Modified by WIDzard Str@wberry
static void set_speaker_l(void)
{
	unsigned int val;

	// read current register values, get corrected value and write back to audio hub
	val = wm8994_read(codec, WM8994_SPEAKER_VOLUME_LEFT);
	val = get_speaker_l(val);
        wm8994_write(codec, WM8994_SPEAKER_VOLUME_LEFT, val);


	
}

// Speaker volume
// Modified by WIDzard Str@wberry
static void set_speaker_r(void)
{
	unsigned int val;



	val = wm8994_read(codec, WM8994_SPEAKER_VOLUME_RIGHT);
	val = get_speaker_r(val);
        wm8994_write(codec, WM8994_SPEAKER_VOLUME_RIGHT, val | WM8994_SPKOUT_VU);

}
static unsigned int get_speaker_l(unsigned int val)
{
	// if privacy mode is on, we set value to zero, otherwise to configured speaker volume
	if((privacy_mode == ON) && is_headphone)
		return (val & ~WM8994_SPKOUTL_VOL_MASK);

	return (val & ~WM8994_SPKOUTL_VOL_MASK) | speaker_l;
}


static unsigned int get_speaker_r(unsigned int val)
{
	// if privacy mode is on, we set value to zero, otherwise to configured speaker volume
	if((privacy_mode == ON) && is_headphone)
		return (val & ~WM8994_SPKOUTR_VOL_MASK);

	return (val & ~WM8994_SPKOUTR_VOL_MASK) | speaker_r;
}


// Equalizer on/off

static void set_eq(void)
{
	unsigned int val;

	// Equalizer will only be switched on in fact if
	// 1. headphone eq is on, there is no call and there is headphone connected -- or --
	// 2. speaker tuning is enabled, there is no call and there is no headphone connected

	// set internal state variables
	if (!is_call && is_headphone && eq != EQ_OFF)
	{
		is_eq = true;
		is_eq_headphone = true;
	}
	else if (!is_call && !is_headphone && speaker_tuning == ON)
	{
		is_eq = true;
		is_eq_headphone = false;
	}
	else
	{
		is_eq = false;
		is_eq_headphone = false;
	}

	// switch equalizer based on internal status
	if (is_eq)
	{
		// switch EQ on + print debug
		val = wm8994_read(codec, WM8994_AIF1_DAC1_EQ_GAINS_1);
		val |= WM8994_AIF1DAC1_EQ_ENA_MASK;
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_GAINS_1, val);

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_eq on\n");
	}
	else
	{
		// switch EQ off + print debug
		val = wm8994_read(codec, WM8994_AIF1_DAC1_EQ_GAINS_1);
		val &= ~WM8994_AIF1DAC1_EQ_ENA_MASK;
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_GAINS_1, val);

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_eq off\n");
	}

	// refresh settings for gains, bands, saturation prevention and speaker boost
	set_eq_gains();
	set_eq_bands();
	set_eq_satprevention();
	set_speaker_boost();
}

// Delayed work to apply settings after a change is detected

static void apply_settings(struct work_struct *work)
{
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: start applying settings after %d micro seconds delay\n", change_delay);

	set_dac_direct();
	set_mic_level();
	set_mono_downmix();
	set_speaker_l();
	set_speaker_r();
	set_headphone_l();
	set_headphone_r();
	set_eq();

	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: done applying settings after %d micro seconds delay\n", change_delay);

	// signal no scheduled work is pending
	apply_settings_work_scheduled = false;
}

// Equalizer gains

static void set_eq_gains(void)
{
	unsigned int val;
	unsigned int gain1, gain2, gain3, gain4, gain5;
	bool change_eq = false;

	// determine gain values based on equalizer mode (headphone vs. speaker tuning)
	if (is_eq_headphone)
	{
		gain1 = eq_gains[0];
		gain2 = eq_gains[1];
		gain3 = eq_gains[2];
		gain4 = eq_gains[3];
		gain5 = eq_gains[4];

		change_eq = true;

		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_eq_gains (headphone) %d %d %d %d %d\n",
				gain1, gain2, gain3, gain4, gain5);
	}
	else if (is_eq)
	{
		gain1 = EQ_GAIN_STUNING_1;
		gain2 = EQ_GAIN_STUNING_2;
		gain3 = EQ_GAIN_STUNING_3;
		gain4 = EQ_GAIN_STUNING_4;
		gain5 = EQ_GAIN_STUNING_5;

		change_eq = true;

		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_eq_gains (speaker) %d %d %d %d %d\n",
				gain1, gain2, gain3, gain4, gain5);
	}

	if (change_eq) {
		// First register
		// read current value from audio hub and mask all bits apart from equalizer enabled bit,
		// add individual gains and write back to audio hub
		val = wm8994_read(codec, WM8994_AIF1_DAC1_EQ_GAINS_1);
		val &= WM8994_AIF1DAC1_EQ_ENA_MASK;
		val = val | ((gain1 + EQ_GAIN_OFFSET) << WM8994_AIF1DAC1_EQ_B1_GAIN_SHIFT);
		val = val | ((gain2 + EQ_GAIN_OFFSET) << WM8994_AIF1DAC1_EQ_B2_GAIN_SHIFT);
		val = val | ((gain3 + EQ_GAIN_OFFSET) << WM8994_AIF1DAC1_EQ_B3_GAIN_SHIFT);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_GAINS_1, val);

		// second register
		// set individual gains and write back to audio hub
		val = ((gain4 + EQ_GAIN_OFFSET) << WM8994_AIF1DAC1_EQ_B4_GAIN_SHIFT);
		val = val | ((gain5 + EQ_GAIN_OFFSET) << WM8994_AIF1DAC1_EQ_B5_GAIN_SHIFT);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_GAINS_2, val);
	}
}


// Equalizer bands

static void set_eq_bands()
{
	// Set band frequencies either for headphone eq or for speaker tuning
	if (is_eq_headphone)
	{
		// set band 1
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_1_A, eq_bands[0][0]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_1_B, eq_bands[0][1]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_1_PG, eq_bands[0][3]);

		// set band 2
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_A, eq_bands[1][0]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_B, eq_bands[1][1]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_C, eq_bands[1][2]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_PG, eq_bands[1][3]);

		// set band 3
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_A, eq_bands[2][0]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_B, eq_bands[2][1]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_C, eq_bands[2][2]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_PG, eq_bands[2][3]);

		// set band 4
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_A, eq_bands[3][0]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_B, eq_bands[3][1]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_C, eq_bands[3][2]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_PG, eq_bands[3][3]);

		// set band 5
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_5_A, eq_bands[4][0]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_5_B, eq_bands[4][1]);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_5_PG, eq_bands[4][3]);

		// print debug info
		if (debug(DEBUG_NORMAL))
		{
			printk("Boeffla-sound: set_eq_bands 1 (headphone) %d %d %d\n",
				eq_bands[0][0], eq_bands[0][1], eq_bands[0][3]);
			printk("Boeffla-sound: set_eq_bands 2 (headphone) %d %d %d %d\n",
				eq_bands[1][0], eq_bands[1][1], eq_bands[1][2], eq_bands[1][3]);
			printk("Boeffla-sound: set_eq_bands 3 (headphone) %d %d %d %d\n",
				eq_bands[2][0], eq_bands[2][1], eq_bands[2][2], eq_bands[2][3]);
			printk("Boeffla-sound: set_eq_bands 4 (headphone) %d %d %d %d\n",
				eq_bands[3][0], eq_bands[3][1], eq_bands[3][2], eq_bands[3][3]);
			printk("Boeffla-sound: set_eq_bands 5 (headphone) %d %d %d\n",
				eq_bands[4][0], eq_bands[4][1], eq_bands[4][3]);
		}
	}
	else if (is_eq)
	{
		// set band 1
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_1_A, EQ_BAND_1_A_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_1_B, EQ_BAND_1_B_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_1_PG, EQ_BAND_1_PG_STUNING);

		// set band 2
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_A, EQ_BAND_2_A_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_B, EQ_BAND_2_B_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_C, EQ_BAND_2_C_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_2_PG, EQ_BAND_2_PG_STUNING);

		// set band 3
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_A, EQ_BAND_3_A_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_B, EQ_BAND_3_B_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_C, EQ_BAND_3_C_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_3_PG, EQ_BAND_3_PG_STUNING);

		// set band 4
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_A, EQ_BAND_4_A_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_B, EQ_BAND_4_B_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_C, EQ_BAND_4_C_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_4_PG, EQ_BAND_4_PG_STUNING);

		// set band 5
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_5_A, EQ_BAND_5_A_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_5_B, EQ_BAND_5_B_STUNING);
		wm8994_write(codec, WM8994_AIF1_DAC1_EQ_BAND_5_PG, EQ_BAND_5_PG_STUNING);

		// print debug info
		if (debug(DEBUG_NORMAL))
		{
			printk("Boeffla-sound: set_eq_bands 1 (speaker) %d %d %d\n",
				EQ_BAND_1_A_STUNING, EQ_BAND_1_B_STUNING, EQ_BAND_1_PG_STUNING);
			printk("Boeffla-sound: set_eq_bands 2 (speaker) %d %d %d %d\n",
				EQ_BAND_2_A_STUNING, EQ_BAND_2_B_STUNING, EQ_BAND_2_C_STUNING, EQ_BAND_2_PG_STUNING);
			printk("Boeffla-sound: set_eq_bands 3 (speaker) %d %d %d %d\n",
				EQ_BAND_3_A_STUNING, EQ_BAND_3_B_STUNING, EQ_BAND_3_C_STUNING, EQ_BAND_3_PG_STUNING);
			printk("Boeffla-sound: set_eq_bands 4 (speaker) %d %d %d %d\n",
				EQ_BAND_4_A_STUNING, EQ_BAND_4_B_STUNING, EQ_BAND_4_C_STUNING, EQ_BAND_4_PG_STUNING);
			printk("Boeffla-sound: set_eq_bands 5 (speaker) %d %d %d\n",
				EQ_BAND_5_A_STUNING, EQ_BAND_5_B_STUNING, EQ_BAND_5_PG_STUNING);
		}
	}
}


// EQ saturation prevention

static void set_eq_satprevention(void)
{
	unsigned int val;

	// read current value for DRC1_1 register, modify value and write back to audio hub
	val = wm8994_read(codec, WM8994_AIF1_DRC1_1);
	val = get_eq_satprevention(1, val);
	wm8994_write(codec, WM8994_AIF1_DRC1_1, val);

	// read current value for DRC1_2 register, modify value and write back to audio hub
	val = wm8994_read(codec, WM8994_AIF1_DRC1_2);
	val = get_eq_satprevention(2, val);
	wm8994_write(codec, WM8994_AIF1_DRC1_2, val);

	// read current value for DRC1_3 register, modify value and write back to audio hub
	val = wm8994_read(codec, WM8994_AIF1_DRC1_3);
	val = get_eq_satprevention(3, val);
	wm8994_write(codec, WM8994_AIF1_DRC1_3, val);

	// read current value for DRC1_4 register, modify value and write back to audio hub
	val = wm8994_read(codec, WM8994_AIF1_DRC1_4);
	val = get_eq_satprevention(4, val);
	wm8994_write(codec, WM8994_AIF1_DRC1_4, val);

	// print debug information
	if (debug(DEBUG_NORMAL))
	{
		// check whether saturation prevention is switched on or off based on
		// real status of EQ and configured EQ mode and speaker tuning
		if (is_eq && is_eq_headphone && eq == EQ_NORMAL)
			printk("Boeffla-sound: set_eq_satprevention to on (headphone)\n");
		else if (is_eq && !is_eq_headphone && eq == EQ_NORMAL)
			printk("Boeffla-sound: set_eq_satprevention to on (speaker)\n");
		else
			printk("Boeffla-sound: set_eq_satprevention to off\n");
	}
}


static unsigned int get_eq_satprevention(int reg_index, unsigned int val)
{
	// EQ mode is for headphone with saturation prevention and EQ is in fact on
	if (is_eq && is_eq_headphone && eq == EQ_NORMAL)
	{
		switch(reg_index)
		{
			case 1:
				// register WM8994_AIF1_DRC1_1
				return AIF1_DRC1_1_PREVENT;

			case 2:
				// register WM8994_AIF1_DRC1_2
				return AIF1_DRC1_2_PREVENT;

			case 3:
				// register WM8994_AIF1_DRC1_3
				return AIF1_DRC1_3_PREVENT;

			case 4:
				// register WM8994_AIF1_DRC1_4
				return AIF1_DRC1_4_PREVENT;
		}
	}

	// EQ mode is for speaker tuning
	if (is_eq && !is_eq_headphone)
	{
		switch(reg_index)
		{
			case 1:
				// register WM8994_AIF1_DRC1_1
				return AIF1_DRC1_1_STUNING;

			case 2:
				// register WM8994_AIF1_DRC1_2
				return AIF1_DRC1_2_STUNING;

			case 3:
				// register WM8994_AIF1_DRC1_3
				return AIF1_DRC1_3_STUNING;

			case 4:
				// register WM8994_AIF1_DRC1_4
				return AIF1_DRC1_4_STUNING;
		}
	}

	// EQ is in fact off or mode is without saturation prevention
	// so the default values are loaded (with DRC switched off)
	switch(reg_index)
	{
		case 1:
			// register WM8994_AIF1_DRC1_1
			return AIF1_DRC1_1_DEFAULT;

		case 2:
			// register WM8994_AIF1_DRC1_2
			return AIF1_DRC1_2_DEFAULT;

		case 3:
			// register WM8994_AIF1_DRC1_3
			return AIF1_DRC1_3_DEFAULT;

		case 4:
			// register WM8994_AIF1_DRC1_4
			return AIF1_DRC1_4_DEFAULT;
	}

	// We should in fact never reach this last return, only in case of errors
	return val;
}


// Speaker boost (for speaker tuning)

static void set_speaker_boost(void)
{
	unsigned int val;

	// Speaker boost gets activated only if EQ mode is for speaker tuning
	if (is_eq && !is_eq_headphone)
	{
		// enable speaker boost by setting the boost volume
		val = wm8994_read(codec, WM8994_CLASSD);
		val = (val & ~WM8994_SPKOUTL_BOOST_MASK) & ~WM8994_SPKOUTR_BOOST_MASK;
		val = val | (SPEAKER_BOOST_TUNED << WM8994_SPKOUTL_BOOST_SHIFT);
		val = val | (SPEAKER_BOOST_TUNED << WM8994_SPKOUTR_BOOST_SHIFT);
		wm8994_write(codec, WM8994_CLASSD, val);

		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: speaker boost on\n");
	}
	else
	{
		// disable speaker boost by resetting to default values
		val = wm8994_read(codec, WM8994_CLASSD);
		val = (val & ~WM8994_SPKOUTL_BOOST_MASK) & ~WM8994_SPKOUTR_BOOST_MASK;
		val = val | (SPEAKER_BOOST_DEFAULT << WM8994_SPKOUTL_BOOST_SHIFT);
		val = val | (SPEAKER_BOOST_DEFAULT << WM8994_SPKOUTR_BOOST_SHIFT);
		wm8994_write(codec, WM8994_CLASSD, val);

		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: speaker boost off\n");
	}
}


// DAC direct

static void set_dac_direct(void)
{
// do not touch dac direct at all if P4NOTE
#ifndef CONFIG_MACH_P4NOTE
	unsigned int val;

	// get current values for output mixers 1 and 2 (l + r) from audio hub
	// modify the data accordingly and write back to audio hub
	val = wm8994_read(codec, WM8994_OUTPUT_MIXER_1);
	val = get_dac_direct_l(val);
	wm8994_write(codec, WM8994_OUTPUT_MIXER_1, val);

	val = wm8994_read(codec, WM8994_OUTPUT_MIXER_2);
	val = get_dac_direct_r(val);
	wm8994_write(codec, WM8994_OUTPUT_MIXER_2, val);

	// take value of the right channel as reference, check for the bypass bit
	// and print debug information
	if (debug(DEBUG_NORMAL))
	{
		if (val & WM8994_DAC1R_TO_HPOUT1R)
			printk("Boeffla-sound: set_dac_direct on\n");
		else
			printk("Boeffla-sound: set_dac_direct off\n");
	}
#endif

}

static unsigned int get_dac_direct_l(unsigned int val)
{
	// dac direct is only enabled if fm radio is not active
	if ((dac_direct == ON) && (!is_fmradio))
		// enable dac_direct: bypass for both channels, mute output mixer
		return((val & ~WM8994_DAC1L_TO_MIXOUTL) | WM8994_DAC1L_TO_HPOUT1L);

	// disable dac_direct: enable bypass for both channels, mute output mixer
	return((val & ~WM8994_DAC1L_TO_HPOUT1L) | WM8994_DAC1L_TO_MIXOUTL);
}

static unsigned int get_dac_direct_r(unsigned int val)
{
	// dac direct is only enabled if fm radio is not active
	if ((dac_direct == ON) && (!is_fmradio))
		// enable dac_direct: bypass for both channels, mute output mixer
		return((val & ~WM8994_DAC1R_TO_MIXOUTR) | WM8994_DAC1R_TO_HPOUT1R);

	// disable dac_direct: enable bypass for both channels, mute output mixer
	return((val & ~WM8994_DAC1R_TO_HPOUT1R) | WM8994_DAC1R_TO_MIXOUTR);
}


// DAC oversampling

static void set_dac_oversampling()
{
	unsigned int val;

	// read current value of oversampling register
	val = wm8994_read(codec, WM8994_OVERSAMPLING);

	// toggle oversampling bit depending on status + print debug
	if (dac_oversampling == ON)
	{
		val |= WM8994_DAC_OSR128;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_oversampling on\n");
	}
	else
	{
		val &= ~WM8994_DAC_OSR128;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_oversampling off\n");
	}

	// write value back to audio hub
	wm8994_write(codec, WM8994_OVERSAMPLING, val);
}


// FLL tuning

static void set_fll_tuning(void)
{
	unsigned int val;

	// read current value of FLL control register 4 and mask out loop gain value
	val = wm8994_read(codec, WM8994_FLL1_CONTROL_4);
	val &= ~WM8994_FLL1_LOOP_GAIN_MASK;

	// depending on whether fll tuning is on or off, modify value accordingly
	// and print debug
	if (fll_tuning == ON)
	{
		val |= FLL_LOOP_GAIN_TUNED;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_fll_tuning on\n");
	}
	else
	{
		val |= FLL_LOOP_GAIN_DEFAULT;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_fll_tuning off\n");
	}

	// write value back to audio hub
	wm8994_write(codec, WM8994_FLL1_CONTROL_4, val);
}


// Stereo expansion

static void set_stereo_expansion(void)
{
	unsigned int val;

	// read current value of DAC1 filter register and mask out gain value and enable bit
	val = wm8994_read(codec, WM8994_AIF1_DAC1_FILTERS_2);
	val &= ~(WM8994_AIF1DAC1_3D_GAIN_MASK);
	val &= ~(WM8994_AIF1DAC1_3D_ENA_MASK);

	// depending on whether stereo expansion is 0 (=off) or not, modify values for gain
	// and enabled bit accordingly, also print debug
	if (stereo_expansion_gain != STEREO_EXPANSION_GAIN_OFF)
	{
		val |= (stereo_expansion_gain << WM8994_AIF1DAC1_3D_GAIN_SHIFT) | WM8994_AIF1DAC1_3D_ENA;

		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_stereo_expansion set to %d\n", stereo_expansion_gain);
	}
	else
	{
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: set_stereo_expansion off\n");
	}

	// write value back to audio hub
	wm8994_write(codec, WM8994_AIF1_DAC1_FILTERS_2, val);
}


// Mono downmix

static void set_mono_downmix(void)
{
	unsigned int val;

// P4Note has stereo speakers, so also allow mono without headphones attached
#ifndef CONFIG_MACH_P4NOTE 
	if (!is_call && is_headphone && (mono_downmix == ON))
#else
	if (!is_call  && (mono_downmix == ON))
#endif  
	{
		if (!is_mono_downmix)
		{
			val = wm8994_read(codec, WM8994_AIF1_DAC1_FILTERS_1);
			wm8994_write(codec, WM8994_AIF1_DAC1_FILTERS_1, val | WM8994_AIF1DAC1_MONO);

			if (debug(DEBUG_NORMAL))
				printk("Boeffla-sound: set_mono_downmix set to on\n");
		}

		is_mono_downmix = true;
	}
	else
	{
		if (is_mono_downmix)
		{
			val = wm8994_read(codec, WM8994_AIF1_DAC1_FILTERS_1);
			wm8994_write(codec, WM8994_AIF1_DAC1_FILTERS_1, val & ~WM8994_AIF1DAC1_MONO);

			if (debug(DEBUG_NORMAL))
				printk("Boeffla-sound: set_mono_downmix set to off\n");
		}

		is_mono_downmix = false;
	}

}


static unsigned int get_mono_downmix(unsigned int val)
{

	if (mono_downmix == OFF)
		return val;

	if (is_mono_downmix)
		return val | WM8994_AIF1DAC1_MONO;

	return val & ~WM8994_AIF1DAC1_MONO;
}


// MIC level

static void set_mic_level(void)
{
	unsigned int val;

	// if mic is not controlled by boeffla-sound, terminate and do nothing
	if (!is_mic_controlled)
		return;

	// check if call is currently active as internal mic sensivity value
	// is dependent on this
	if (is_call)
		mic_level = mic_level_call;
	else
		mic_level = mic_level_general;

	// set input volume for both input channels
	val = wm8994_read(codec, WM8994_LEFT_LINE_INPUT_1_2_VOLUME);
	wm8994_write(codec, WM8994_LEFT_LINE_INPUT_1_2_VOLUME, get_mic_level(1, 0));

	val = wm8994_read(codec, WM8994_RIGHT_LINE_INPUT_1_2_VOLUME);
	wm8994_write(codec, WM8994_RIGHT_LINE_INPUT_1_2_VOLUME, get_mic_level(2, 0));

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: set_mic_level %d\n", mic_level);
}


static unsigned int get_mic_level(int reg_index, unsigned int val)
{

	// check if mic is currently controlled by boeffla-sound
	// if not, the value is returned back unchanged to not impact the microphone at all
	if (!is_mic_controlled)
		return val;

	// send changed values back
	switch (reg_index)
	{
		//  Register WM8994_LEFT_LINE_INPUT_1_2_VOLUME
		case 1:
			return(mic_level | WM8994_IN1_VU);
			break;

		//  Register WM8994_RIGHT_LINE_INPUT_1_2_VOLUME
		case 2:
			return(mic_level | WM8994_IN1_VU);
			break;
	}

	// we should never reach this point ideally, but in error case return original value
	return val;
}


// Initialization functions

static void initialize_global_variables(void)
{
	// set global variables to standard values

	headphone_l = HEADPHONE_DEFAULT;
	headphone_r = HEADPHONE_DEFAULT;

	speaker_l = SPEAKER_DEFAULT;
	speaker_r = SPEAKER_DEFAULT;

	speaker_tuning = OFF;

	eq = EQ_DEFAULT;

	eq_gains[0] = EQ_GAIN_DEFAULT;
	eq_gains[1] = EQ_GAIN_DEFAULT;
	eq_gains[2] = EQ_GAIN_DEFAULT;
	eq_gains[3] = EQ_GAIN_DEFAULT;
	eq_gains[4] = EQ_GAIN_DEFAULT;

	eq_bands[0][0] = EQ_BAND_1_A_DEFAULT;
	eq_bands[0][1] = EQ_BAND_1_B_DEFAULT;
	eq_bands[0][3] = EQ_BAND_1_PG_DEFAULT;
	eq_bands[1][0] = EQ_BAND_2_A_DEFAULT;
	eq_bands[1][1] = EQ_BAND_2_B_DEFAULT,
	eq_bands[1][2] = EQ_BAND_2_C_DEFAULT,
	eq_bands[1][3] = EQ_BAND_2_PG_DEFAULT;
	eq_bands[2][0] = EQ_BAND_3_A_DEFAULT;
	eq_bands[2][1] = EQ_BAND_3_B_DEFAULT;
	eq_bands[2][2] = EQ_BAND_3_C_DEFAULT;
	eq_bands[2][3] = EQ_BAND_3_PG_DEFAULT;
	eq_bands[3][0] = EQ_BAND_4_A_DEFAULT;
	eq_bands[3][1] = EQ_BAND_4_B_DEFAULT;
	eq_bands[3][2] = EQ_BAND_4_C_DEFAULT;
	eq_bands[3][3] = EQ_BAND_4_PG_DEFAULT;
	eq_bands[4][0] = EQ_BAND_5_A_DEFAULT;
	eq_bands[4][1] = EQ_BAND_5_B_DEFAULT;
	eq_bands[4][3] = EQ_BAND_5_PG_DEFAULT;

	dac_direct = OFF;

	dac_oversampling = OFF;

	fll_tuning = OFF;

	stereo_expansion_gain = STEREO_EXPANSION_GAIN_OFF;

	mono_downmix = OFF;

	privacy_mode = OFF;

	mic_level_general = MICLEVEL_GENERAL;
	mic_level_call = MICLEVEL_CALL;
	mic_level = MICLEVEL_GENERAL;

	debug_register = 0;

	is_call = false;
	is_headphone = false;
	is_fmradio = false;

	is_eq = false;
	is_eq_headphone = false;
	is_mic_controlled=false;
	is_mono_downmix = false;

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: initialize_global_variables completed\n");
}


static void reset_boeffla_sound(void)
{
	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: reset_boeffla_sound started\n");

	// load all default values
	initialize_global_variables();

	// initialize headphone, call and fm radio status
	is_call = check_for_call();
	is_headphone = check_for_headphone();
	is_fmradio = check_for_fmradio();

	// set headphone volumes to defaults
	set_headphone_l();
	set_headphone_r();
	
	// set speaker volumes to defaults
	set_speaker_l();
	set_speaker_r();

	// reset equalizer mode
	// (this also resets gains, bands, saturation prevention and speaker boost)
	set_eq();

	// reset DAC_direct
	set_dac_direct();

	// reset DAC oversampling
	set_dac_oversampling();

	// reset FLL tuning
	set_fll_tuning();

	// reset stereo expansion
	set_stereo_expansion();

	// reset mono downmix
	set_mono_downmix();

	// reset mic level
	set_mic_level();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: reset_boeffla_sound completed\n");
}



/*****************************************/
// sysfs interface functions
/*****************************************/

// Boeffla sound master switch

static ssize_t boeffla_sound_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current value Boeffla sound status: 
	return sprintf(buf, "%d\n", boeffla_sound);
}


static ssize_t boeffla_sound_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val;

	// read values from input buffer
	ret = sscanf(buf, "%d", &val);

	// store if valid data and only if status has changed, reset all values
	if (((val == OFF) || (val == ON))&& (val != boeffla_sound))
	{
		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: status %d\n", boeffla_sound);

		// Initialize Boeffla-Sound
		boeffla_sound = val;
		reset_boeffla_sound();
	}

	return count;
}


// Headphone volume Left
// Modified by WIDzard Str@wberry
static ssize_t headphone_volume_show_l(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values Headphone volume: LEFT/RIGHT
	return sprintf(buf, "%d\n", headphone_l);
}


static ssize_t headphone_volume_store_l(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val_l;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d", &val_l);

	// check whether values are within the valid ranges and adjust accordingly
	if (val_l > HEADPHONE_MAX)
		val_l = HEADPHONE_MAX;

	if (val_l < HEADPHONE_MIN)
		val_l = HEADPHONE_MIN;

	// store values into global variables
	headphone_l = val_l;

	// set new values
	set_headphone_l();

	return count;
}

// Headphone volume RIGHT
// Modified by WIDzard Str@wberry
static ssize_t headphone_volume_show_r(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values Headphone volume: LEFT/RIGHT
	return sprintf(buf, "%d\n", headphone_r);
}


static ssize_t headphone_volume_store_r(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val_r;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d", &val_r);

	// check whether values are within the valid ranges and adjust accordingly

	if (val_r > HEADPHONE_MAX)
		val_r = HEADPHONE_MAX;

	if (val_r < HEADPHONE_MIN)
		val_r = HEADPHONE_MIN;

	// store values into global variables
	headphone_r = val_r;

	// set new values
	set_headphone_r();


	return count;
}

// Speaker volume Left
// Modified by WIDzard Str@wberry
static ssize_t speaker_volume_show_l(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", speaker_l);

}


static ssize_t speaker_volume_store_l(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val_l;


	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &val_l);

	// check whether values are within the valid ranges and adjust accordingly
	if (val_l > SPEAKER_MAX)
		val_l = SPEAKER_MAX;

	if (val_l < SPEAKER_MIN)
		val_l = SPEAKER_MIN;

	// store values into global variables
	speaker_l = val_l;

	// set new values
	set_speaker_l();


	return count;
}
// Speaker volume Right
// Modified by WIDzard Str@wberry
static ssize_t speaker_volume_show_r(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values Speaker volume:\nLeft: Right: 
	return sprintf(buf, "%d\n", speaker_r);

}


static ssize_t speaker_volume_store_r(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val_r;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &val_r);

	// check whether values are within the valid ranges and adjust accordingly
	if (val_r > SPEAKER_MAX)
		val_r = SPEAKER_MAX;

	if (val_r < SPEAKER_MIN)
		val_r = SPEAKER_MIN;

	// store values into global variables
	speaker_r = val_r;

	// set new values
	set_speaker_r();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: speaker volume R=%d\n", speaker_r);

	return count;
}


// Speaker tuning

static ssize_t speaker_tuning_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current value Speaker tuning: 
	return sprintf(buf, "%d\n", speaker_tuning);
}

static ssize_t speaker_tuning_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read value from input buffer, check validity and update audio hub
	ret = sscanf(buf, "%d", &val);

	if ((val == ON) || (val == OFF))
	{
		speaker_tuning = val;
		set_eq();
	}

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: DAC oversampling %d\n", dac_oversampling);

	return count;
}

// Equalizer mode

static ssize_t eq_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current value EQ: 
	return sprintf(buf, "%d\n", eq);
}


static ssize_t eq_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer and update audio hub
	ret = sscanf(buf, "%d", &val);

	if (((val >= EQ_OFF) && (val <= EQ_NOSATPREVENT)) && (val != eq))
		eq = val;
	set_eq();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: EQ %d\n", eq);

	return count;
}


// Equalizer gains-0
// Modified by WIDzard Str@wberry
static ssize_t eq_gains_show_0(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values EQ gains: 
	return sprintf(buf, "%d\n", eq_gains[0]);
}


static ssize_t eq_gains_store_0(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int gains[5];
	int i;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &gains[0]);

	// check validity of gain values and adjust

		if (gains[0] < EQ_GAIN_MIN)
			gains[0] = EQ_GAIN_MIN;

		if (gains[0] > EQ_GAIN_MAX)
			gains[0] = EQ_GAIN_MAX;

		eq_gains[0] = gains[0];

	// set new values
	set_eq_gains();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: EQ gains %d\n", eq_gains[0]);

	return count;
}
// Equalizer gains-1
// Modified by WIDzard Str@wberry
static ssize_t eq_gains_show_1(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values EQ gains: 
	return sprintf(buf, "%d\n", eq_gains[1]);
}


static ssize_t eq_gains_store_1(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int gains[5];
	int i;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &gains[1]);

	// check validity of gain values and adjust

		if (gains[1] < EQ_GAIN_MIN)
			gains[1] = EQ_GAIN_MIN;

		if (gains[1] > EQ_GAIN_MAX)
			gains[1] = EQ_GAIN_MAX;

		eq_gains[1] = gains[1];

	// set new values
	set_eq_gains();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: EQ gains %d\n", eq_gains[1]);

	return count;
}
// Equalizer gains-2
// Modified by WIDzard Str@wberry
static ssize_t eq_gains_show_2(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values EQ gains: 
	return sprintf(buf, "%d\n", eq_gains[2]);
}


static ssize_t eq_gains_store_2(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int gains[5];
	int i;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &gains[2]);

	// check validity of gain values and adjust

		if (gains[2] < EQ_GAIN_MIN)
			gains[2] = EQ_GAIN_MIN;

		if (gains[2] > EQ_GAIN_MAX)
			gains[2] = EQ_GAIN_MAX;

		eq_gains[2] = gains[2];

	// set new values
	set_eq_gains();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: EQ gains %d\n", eq_gains[2]);

	return count;
}
// Equalizer gains-3
// Modified by WIDzard Str@wberry
static ssize_t eq_gains_show_3(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values EQ gains: 
	return sprintf(buf, "%d\n", eq_gains[3]);
}


static ssize_t eq_gains_store_3(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int gains[5];
	int i;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &gains[3]);

	// check validity of gain values and adjust

		if (gains[3] < EQ_GAIN_MIN)
			gains[3] = EQ_GAIN_MIN;

		if (gains[3] > EQ_GAIN_MAX)
			gains[3] = EQ_GAIN_MAX;

		eq_gains[3] = gains[3];

	// set new values
	set_eq_gains();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: EQ gains %d\n", eq_gains[3]);

	return count;
}

// Equalizer gains-4
// Modified by WIDzard Str@wberry
static ssize_t eq_gains_show_4(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values EQ gains: 
	return sprintf(buf, "%d\n", eq_gains[4]);
}


static ssize_t eq_gains_store_4(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int gains[5];
	int i;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &gains[4]);

	// check validity of gain values and adjust

		if (gains[4] < EQ_GAIN_MIN)
			gains[4] = EQ_GAIN_MIN;

		if (gains[4] > EQ_GAIN_MAX)
			gains[4] = EQ_GAIN_MAX;

		eq_gains[4] = gains[4];

	// set new values
	set_eq_gains();

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: EQ gains %d\n", eq_gains[4]);

	return count;
}

// Equalizer bands - 00
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_00(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[0][0]);
}


static ssize_t eq_bands_store_00(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 1;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][0] = v1;

	// set new values
	set_eq_bands();

	return count;
}


// Equalizer bands - 01
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_01(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[0][1]);
}


static ssize_t eq_bands_store_01(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 1;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][1] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 02

static ssize_t eq_bands_show_02(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", 0);

}


static ssize_t eq_bands_store_02(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 1;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][2] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 03
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_03(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[0][3]);
}


static ssize_t eq_bands_store_03(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 1;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][3] = v1;

	// set new values
	set_eq_bands();

	return count;
}

/////////////////////////////
// Equalizer bands - 10
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_10(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[1][0]);
}


static ssize_t eq_bands_store_10(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 2;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][0] = v1;

	// set new values
	set_eq_bands();

	return count;
}


// Equalizer bands - 11
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_11(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[1][1]);
}


static ssize_t eq_bands_store_11(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 2;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][1] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 12
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_12(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[1][2]);

}


static ssize_t eq_bands_store_12(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 2;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][2] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 13
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_13(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[1][3]);
}


static ssize_t eq_bands_store_13(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 2;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][3] = v1;

	// set new values
	set_eq_bands();

	return count;
}
/////////////////////////////
// Equalizer bands - 20
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_20(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[2][0]);
}


static ssize_t eq_bands_store_20(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 3;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][0] = v1;

	// set new values
	set_eq_bands();

	return count;
}


// Equalizer bands - 21
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_21(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[2][1]);
}


static ssize_t eq_bands_store_21(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 3;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][1] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 22
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_22(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[2][2]);

}


static ssize_t eq_bands_store_22(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 3;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][2] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 23
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_23(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[2][3]);
}


static ssize_t eq_bands_store_23(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 3;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][3] = v1;

	// set new values
	set_eq_bands();

	return count;
}
/////////////////////////////
// Equalizer bands - 30
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_30(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[3][0]);
}


static ssize_t eq_bands_store_30(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 3;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][0] = v1;

	// set new values
	set_eq_bands();

	return count;
}


// Equalizer bands - 31
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_31(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[3][1]);
}


static ssize_t eq_bands_store_31(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 4;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][1] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 32
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_32(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[3][2]);

}


static ssize_t eq_bands_store_32(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 4;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][2] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 33
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_33(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[3][3]);
}


static ssize_t eq_bands_store_33(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 4;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][3] = v1;

	// set new values
	set_eq_bands();

	return count;
}
/////////////////////////////
// Equalizer bands - 40
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_40(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[4][0]);
}


static ssize_t eq_bands_store_40(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 5;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][0] = v1;

	// set new values
	set_eq_bands();

	return count;
}


// Equalizer bands - 41
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_41(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[4][1]);
}


static ssize_t eq_bands_store_41(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 5;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][1] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 42
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_42(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", 0);

}


static ssize_t eq_bands_store_42(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 5;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][2] = v1;

	// set new values
	set_eq_bands();

	return count;
}

// Equalizer bands - 43
// Modified by WIDzard Str@wberry
static ssize_t eq_bands_show_43(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current values
	return sprintf(buf, "%d\n", eq_bands[4][3]);
}


static ssize_t eq_bands_store_43(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int band, v1;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d\n", &v1);
	band = 5;
	// check input data for validity, terminate if not valid
	if ((band < 1) || (band > 5))
		return count;

	eq_bands[band-1][3] = v1;

	// set new values
	set_eq_bands();

	return count;
}
// DAC direct

static ssize_t dac_direct_show(struct device *dev, struct device_attribute *attr, char *buf)
{
// For P4NOTE, dac direct always needs to be enabled, so the setting is
// returned as blank = setting not active DAC direct: 
#ifndef CONFIG_MACH_P4NOTE
	return sprintf(buf, "%d\n", dac_direct);
#else
	return 0;
#endif
}


static ssize_t dac_direct_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer, check validity and update audio hub
	ret = sscanf(buf, "%d", &val);

	if ((val == ON) || (val == OFF))
	{
		dac_direct = val;
		set_dac_direct();
	}

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: DAC direct %d\n", dac_direct);

	return count;
}


// DAC oversampling

static ssize_t dac_oversampling_show(struct device *dev, struct device_attribute *attr, char *buf)
{
//DAC oversampling: 
	return sprintf(buf, "%d\n", dac_oversampling);
}


static ssize_t dac_oversampling_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer, check validity and update audio hub
	ret = sscanf(buf, "%d", &val);

	if ((val == ON) || (val == OFF))
	{
		dac_oversampling = val;
		set_dac_oversampling();
	}

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: DAC oversampling %d\n", dac_oversampling);

	return count;
}


// FLL tuning

static ssize_t fll_tuning_show(struct device *dev, struct device_attribute *attr, char *buf)
{
//FLL tuning: 
	return sprintf(buf, "%d\n", fll_tuning);
}


static ssize_t fll_tuning_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer, check validity and update audio hub
	ret = sscanf(buf, "%d", &val);

	if ((val == ON) || (val == OFF))
	{
		fll_tuning = val;
		set_fll_tuning();
	}

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: FLL tuning %d\n", fll_tuning);

	return count;
}


// Stereo expansion

static ssize_t stereo_expansion_show(struct device *dev, struct device_attribute *attr, char *buf)
{
//Stereo expansion: 
	return sprintf(buf, "%d\n", stereo_expansion_gain);
}


static ssize_t stereo_expansion_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer, check validity and update audio hub
	ret = sscanf(buf, "%d", &val);

	if ((val >= STEREO_EXPANSION_GAIN_MIN) && (val <= STEREO_EXPANSION_GAIN_MAX))
	{
		stereo_expansion_gain = val;
		set_stereo_expansion();
	}

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: Stereo expansion %d\n", stereo_expansion_gain);

	return count;
}


// Mono downmix Mono downmix: 

static ssize_t mono_downmix_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", mono_downmix);
}


static ssize_t mono_downmix_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer
	ret = sscanf(buf, "%d", &val);

	// update only if new value is valid and has changed
	if (((val == ON) || (val == OFF)) && (val != mono_downmix))
	{
		mono_downmix = val;
		set_mono_downmix();

		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: Mono downmix %d\n", mono_downmix);
	}

	return count;
}


// Privacy mode Privacy mode: 

static ssize_t privacy_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", privacy_mode);
}


static ssize_t privacy_mode_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read values from input buffer, check validity and update audio hub
	ret = sscanf(buf, "%d", &val);

	if ((val == ON) || (val == OFF))
	{
		privacy_mode = val;
		set_speaker_l();
		set_speaker_r();
	}

	// print debug info
	if (debug(DEBUG_NORMAL))
		printk("Boeffla-sound: Privacy mode %d\n", privacy_mode);

	return count;
}


// Microphone levels Mic level general 

static ssize_t mic_level_general_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", mic_level_general);
}


static ssize_t mic_level_general_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read value for mic level from input buffer
	ret = sscanf(buf, "%d", &val);

	// check validity of data
	if ((val >= MICLEVEL_MIN) && (val <= MICLEVEL_MAX))
	{
		// only do something if the value has changed
		if (mic_level_general != val)
		{
			mic_level_general = val;

			// from now on, boeffla-sound controls the microphone exclusively
			is_mic_controlled = true;

			// set mic level now
			set_mic_level();

			// print debug info
			if (debug(DEBUG_NORMAL))
				printk("Boeffla-sound: Mic level general %d\n", mic_level_general);
		}
	}

	// Just in case the mic levels for both general and call have been reset
	// to defaults, Boeffla-Sound releases control over the microphone again
	if ((mic_level_general == MICLEVEL_GENERAL) && (mic_level_call == MICLEVEL_CALL))
		is_mic_controlled = false;

	return count;
}

static ssize_t mic_level_call_show(struct device *dev, struct device_attribute *attr, char *buf)
{
//Mic level call 
	return sprintf(buf, "%d\n", mic_level_call);
}


static ssize_t mic_level_call_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// Terminate instantly if boeffla sound is not enabled
	if (!boeffla_sound)
		return count;

	// read value for mic level from input buffer
	ret = sscanf(buf, "%d", &val);

	// check validity of data
	if ((val >= MICLEVEL_MIN) && (val <= MICLEVEL_MAX))
	{
		// only do something if the value has changed
		if (mic_level_call != val)
		{
			mic_level_call = val;

			// from now on, boeffla-sound controls the microphone exclusively
			is_mic_controlled = true;

			// set mic level now
			set_mic_level();

			// print debug info
			if (debug(DEBUG_NORMAL))
				printk("Boeffla-sound: Mic level call %d\n", mic_level_call);
		}
	}

	// Just in case the mic levels for both general and call have been reset
	// to defaults, Boeffla-Sound releases control over the microphone again
	if ((mic_level_general == MICLEVEL_GENERAL) && (mic_level_call == MICLEVEL_CALL))
		is_mic_controlled = false;

	return count;
}


// Debug level

static ssize_t debug_level_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	// return current debug level
	// (this exceptionally also works when boeffla-sound is disabled)
	// Debug level: 
	return sprintf(buf, "%d\n", debug_level);
}


static ssize_t debug_level_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// check data and store if valid
	ret = sscanf(buf, "%d", &val);

	if ((val >= 0) && (val <= 2))
		debug_level = val;

	return count;
}


// Debug info

static ssize_t debug_info_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	unsigned int val;

	// start with version info Boeffla-Sound version: 
	sprintf(buf, "%s\n\n", BOEFFLA_SOUND_VERSION);

	// read values of some interesting registers and put them into a string
	val = wm8994_read(codec, WM8994_AIF2_CONTROL_2);
	sprintf(buf+strlen(buf), "WM8994_AIF2_CONTROL_2: %d\n", val);

	val = wm8994_read(codec, WM8994_LEFT_OUTPUT_VOLUME);
	sprintf(buf+strlen(buf), "WM8994_LEFT_OUTPUT_VOLUME: %d\n", val);

	val = wm8994_read(codec, WM8994_RIGHT_OUTPUT_VOLUME);
	sprintf(buf+strlen(buf), "WM8994_RIGHT_OUTPUT_VOLUME: %d\n", val);

	val = wm8994_read(codec, WM8994_SPEAKER_VOLUME_LEFT);
	sprintf(buf+strlen(buf), "WM8994_SPEAKER_VOLUME_LEFT: %d\n", val);

	val = wm8994_read(codec, WM8994_SPEAKER_VOLUME_RIGHT);
	sprintf(buf+strlen(buf), "WM8994_SPEAKER_VOLUME_RIGHT: %d\n", val);

	val = wm8994_read(codec, WM8994_CLASSD);
	sprintf(buf+strlen(buf), "WM8994_CLASSD: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DAC1_EQ_GAINS_1);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DAC1_EQ_GAINS_1: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DAC1_EQ_GAINS_2);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DAC1_EQ_GAINS_2: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DRC1_1);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DRC1_1: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DRC1_2);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DRC1_2: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DRC1_3);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DRC1_3: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DRC1_4);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DRC1_4: %d\n", val);

	val = wm8994_read(codec, WM8994_OUTPUT_MIXER_1);
	sprintf(buf+strlen(buf), "WM8994_OUTPUT_MIXER_1: %d\n", val);

	val = wm8994_read(codec, WM8994_OUTPUT_MIXER_2);
	sprintf(buf+strlen(buf), "WM8994_OUTPUT_MIXER_2: %d\n", val);

	val = wm8994_read(codec, WM8994_OVERSAMPLING);
	sprintf(buf+strlen(buf), "WM8994_OVERSAMPLING: %d\n", val);

	val = wm8994_read(codec, WM8994_FLL1_CONTROL_4);
	sprintf(buf+strlen(buf), "WM8994_FLL1_CONTROL_4: %d\n", val);

	val = wm8994_read(codec, WM8994_LEFT_LINE_INPUT_1_2_VOLUME);
	sprintf(buf+strlen(buf), "WM8994_LEFT_LINE_INPUT_1_2_VOLUME: %d\n", val);

	val = wm8994_read(codec, WM8994_RIGHT_LINE_INPUT_1_2_VOLUME);
	sprintf(buf+strlen(buf), "WM8994_RIGHT_LINE_INPUT_1_2_VOLUME: %d\n", val);

	val = wm8994_read(codec, WM8994_INPUT_MIXER_3);
	sprintf(buf+strlen(buf), "WM8994_INPUT_MIXER_3: %d\n", val);

	val = wm8994_read(codec, WM8994_INPUT_MIXER_4);
	sprintf(buf+strlen(buf), "WM8994_INPUT_MIXER_4: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DAC1_FILTERS_1);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DAC1_FILTERS_1: %d\n", val);

	val = wm8994_read(codec, WM8994_AIF1_DAC1_FILTERS_2);
	sprintf(buf+strlen(buf), "WM8994_AIF1_DAC1_FILTERS_2: %d\n", val);

	// add the current states of call, headphone and fmradio
	sprintf(buf+strlen(buf), "is_call:%d is_headphone:%d is_fmradio:%d\n",
				is_call, is_headphone, is_fmradio);

	// add the current states of internal headphone handling and mono downmix
	sprintf(buf+strlen(buf), "is_eq:%d is_eq_headphone: %d is_mono_downmix: %d\n",
				is_eq, is_eq_headphone, is_mono_downmix);

	// finally add the current states of internal mic level, gain and control state
	sprintf(buf+strlen(buf), "mic_level: %d is_mic_controlled: %d\n",
				mic_level, is_mic_controlled);

	// return buffer length back
	return strlen(buf);
}


static ssize_t debug_info_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	// this function has no function, but can be misused for some debugging/testing
	return count;
}


// Debug register

static ssize_t debug_reg_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int val;

	// read current debug register value from audio hub and return value back
	val = wm8994_read(codec, debug_register);
	return sprintf(buf, "%d -> %d", debug_register, val);
}


static ssize_t debug_reg_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val1 = 0;
	unsigned int val2;

	// read values from input buffer and update audio hub (if requested via key)
	ret = sscanf(buf, "%d %d %d", &debug_register, &val1, &val2);

	if (val1 == DEBUG_REGISTER_KEY)
		wm8994_write(codec, debug_register, val2);

	return count;
}


// Debug dump

static ssize_t debug_dump_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	unsigned int val;
	int i;

	// read selected bank, compare with cache and print results
	for (i = regdump_bank*REGDUMP_REGISTERS; i <= (regdump_bank+1)*REGDUMP_REGISTERS; i++)
	{
		val = wm8994_read(codec, i);

		if(regcache[i] != val)
			sprintf(buf+strlen(buf), "%d: %d -> %d\n", i, regcache[i], val);
		else
			sprintf(buf+strlen(buf), "%d: %d\n", i, val);

		regcache[i] = val;
	}

	// return buffer length back
	return strlen(buf);
}


static ssize_t debug_dump_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	unsigned int val;

	// read value from input buffer and set bank accordingly
	ret = sscanf(buf, "%d", &val);

	if ((val >= 0) && (val < REGDUMP_BANKS))
		regdump_bank = val;

	return count;
}


// Change delay

static ssize_t change_delay_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	// print current value Boeffla change delay: 
	return sprintf(buf, "%d\n", change_delay);
}


static ssize_t change_delay_store(struct device *dev, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int ret = -EINVAL;
	int val;

	// read values from input buffer
	ret = sscanf(buf, "%d", &val);

	// store if valid data and only if status has changed, reset all values
	if ((val >= MIN_CHANGE_DELAY) && (val <= MAX_CHANGE_DELAY))
	{
		// print debug info
		if (debug(DEBUG_NORMAL))
			printk("Boeffla-sound: change delay %d micro seconds\n", change_delay);

		// Store new change delay
		change_delay = val;

		return count;
	}

	return -EINVAL;
}


// Version information

static ssize_t version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	// return version information
	return sprintf(buf, "%s\n", BOEFFLA_SOUND_VERSION);
}



/*****************************************/
// Initialize boeffla sound sysfs folder
/*****************************************/

// define objects
static DEVICE_ATTR(boeffla_sound, S_IRUGO | S_IWUGO, boeffla_sound_show, boeffla_sound_store);
static DEVICE_ATTR(headphone_volume_left, S_IRUGO | S_IWUGO, headphone_volume_show_l, headphone_volume_store_l);
static DEVICE_ATTR(headphone_volume_right, S_IRUGO | S_IWUGO, headphone_volume_show_r, headphone_volume_store_r);
static DEVICE_ATTR(speaker_volume_left, S_IRUGO | S_IWUGO, speaker_volume_show_l, speaker_volume_store_l);
static DEVICE_ATTR(speaker_volume_right, S_IRUGO | S_IWUGO, speaker_volume_show_r, speaker_volume_store_r);
static DEVICE_ATTR(speaker_tuning, S_IRUGO | S_IWUGO, speaker_tuning_show, speaker_tuning_store);
static DEVICE_ATTR(privacy_mode, S_IRUGO | S_IWUGO, privacy_mode_show, privacy_mode_store);
static DEVICE_ATTR(eq, S_IRUGO | S_IWUGO, eq_show, eq_store);
static DEVICE_ATTR(eq_gains_0, S_IRUGO | S_IWUGO, eq_gains_show_0, eq_gains_store_0);
static DEVICE_ATTR(eq_gains_1, S_IRUGO | S_IWUGO, eq_gains_show_1, eq_gains_store_1);
static DEVICE_ATTR(eq_gains_2, S_IRUGO | S_IWUGO, eq_gains_show_2, eq_gains_store_2);
static DEVICE_ATTR(eq_gains_3, S_IRUGO | S_IWUGO, eq_gains_show_3, eq_gains_store_3);
static DEVICE_ATTR(eq_gains_4, S_IRUGO | S_IWUGO, eq_gains_show_4, eq_gains_store_4);
static DEVICE_ATTR(eq_bands_00, S_IRUGO | S_IWUGO, eq_bands_show_00, eq_bands_store_00);
static DEVICE_ATTR(eq_bands_01, S_IRUGO | S_IWUGO, eq_bands_show_01, eq_bands_store_01);
static DEVICE_ATTR(eq_bands_02, S_IRUGO | S_IWUGO, eq_bands_show_02, eq_bands_store_02);
static DEVICE_ATTR(eq_bands_03, S_IRUGO | S_IWUGO, eq_bands_show_03, eq_bands_store_03);
static DEVICE_ATTR(eq_bands_10, S_IRUGO | S_IWUGO, eq_bands_show_10, eq_bands_store_10);
static DEVICE_ATTR(eq_bands_11, S_IRUGO | S_IWUGO, eq_bands_show_11, eq_bands_store_11);
static DEVICE_ATTR(eq_bands_12, S_IRUGO | S_IWUGO, eq_bands_show_12, eq_bands_store_12);
static DEVICE_ATTR(eq_bands_13, S_IRUGO | S_IWUGO, eq_bands_show_13, eq_bands_store_13);
static DEVICE_ATTR(eq_bands_20, S_IRUGO | S_IWUGO, eq_bands_show_20, eq_bands_store_20);
static DEVICE_ATTR(eq_bands_21, S_IRUGO | S_IWUGO, eq_bands_show_21, eq_bands_store_21);
static DEVICE_ATTR(eq_bands_22, S_IRUGO | S_IWUGO, eq_bands_show_22, eq_bands_store_22);
static DEVICE_ATTR(eq_bands_23, S_IRUGO | S_IWUGO, eq_bands_show_23, eq_bands_store_23);
static DEVICE_ATTR(eq_bands_30, S_IRUGO | S_IWUGO, eq_bands_show_30, eq_bands_store_30);
static DEVICE_ATTR(eq_bands_31, S_IRUGO | S_IWUGO, eq_bands_show_31, eq_bands_store_31);
static DEVICE_ATTR(eq_bands_32, S_IRUGO | S_IWUGO, eq_bands_show_32, eq_bands_store_32);
static DEVICE_ATTR(eq_bands_33, S_IRUGO | S_IWUGO, eq_bands_show_33, eq_bands_store_33);
static DEVICE_ATTR(eq_bands_40, S_IRUGO | S_IWUGO, eq_bands_show_40, eq_bands_store_40);
static DEVICE_ATTR(eq_bands_41, S_IRUGO | S_IWUGO, eq_bands_show_41, eq_bands_store_41);
static DEVICE_ATTR(eq_bands_42, S_IRUGO | S_IWUGO, eq_bands_show_42, eq_bands_store_42);
static DEVICE_ATTR(eq_bands_43, S_IRUGO | S_IWUGO, eq_bands_show_43, eq_bands_store_43);
static DEVICE_ATTR(dac_direct, S_IRUGO | S_IWUGO, dac_direct_show, dac_direct_store);
static DEVICE_ATTR(dac_oversampling, S_IRUGO | S_IWUGO, dac_oversampling_show, dac_oversampling_store);
static DEVICE_ATTR(fll_tuning, S_IRUGO | S_IWUGO, fll_tuning_show, fll_tuning_store);
static DEVICE_ATTR(stereo_expansion, S_IRUGO | S_IWUGO, stereo_expansion_show, stereo_expansion_store);
static DEVICE_ATTR(mono_downmix, S_IRUGO | S_IWUGO, mono_downmix_show, mono_downmix_store);
static DEVICE_ATTR(mic_level_general, S_IRUGO | S_IWUGO, mic_level_general_show, mic_level_general_store);
static DEVICE_ATTR(mic_level_call, S_IRUGO | S_IWUGO, mic_level_call_show, mic_level_call_store);
static DEVICE_ATTR(debug_level, S_IRUGO | S_IWUGO, debug_level_show, debug_level_store);
static DEVICE_ATTR(debug_info, S_IRUGO | S_IWUGO, debug_info_show, debug_info_store);
static DEVICE_ATTR(debug_reg, S_IRUGO | S_IWUGO, debug_reg_show, debug_reg_store);
static DEVICE_ATTR(debug_dump, S_IRUGO | S_IWUGO, debug_dump_show, debug_dump_store);
static DEVICE_ATTR(change_delay, S_IRUGO | S_IWUGO, change_delay_show, change_delay_store);
static DEVICE_ATTR(version, S_IRUGO | S_IWUGO, version_show, NULL);

// define attributes
static struct attribute *boeffla_sound_attributes[] = {
	&dev_attr_boeffla_sound.attr,
	&dev_attr_headphone_volume_left.attr,
	&dev_attr_headphone_volume_right.attr,
	&dev_attr_speaker_volume_left.attr,
	&dev_attr_speaker_volume_right.attr,
	&dev_attr_speaker_tuning.attr,
	&dev_attr_privacy_mode.attr,
	&dev_attr_eq.attr,
	&dev_attr_eq_gains_0.attr,
	&dev_attr_eq_gains_1.attr,
	&dev_attr_eq_gains_2.attr,
	&dev_attr_eq_gains_3.attr,
	&dev_attr_eq_gains_4.attr,
	&dev_attr_eq_bands_00.attr,
	&dev_attr_eq_bands_01.attr,
	&dev_attr_eq_bands_02.attr,
	&dev_attr_eq_bands_03.attr,
	&dev_attr_eq_bands_10.attr,
	&dev_attr_eq_bands_11.attr,
	&dev_attr_eq_bands_12.attr,
	&dev_attr_eq_bands_13.attr,
	&dev_attr_eq_bands_20.attr,
	&dev_attr_eq_bands_21.attr,
	&dev_attr_eq_bands_22.attr,
	&dev_attr_eq_bands_23.attr,
	&dev_attr_eq_bands_30.attr,
	&dev_attr_eq_bands_31.attr,
	&dev_attr_eq_bands_32.attr,
	&dev_attr_eq_bands_33.attr,
	&dev_attr_eq_bands_40.attr,
	&dev_attr_eq_bands_41.attr,
	&dev_attr_eq_bands_42.attr,
	&dev_attr_eq_bands_43.attr,	
	&dev_attr_dac_direct.attr,
	&dev_attr_dac_oversampling.attr,
	&dev_attr_fll_tuning.attr,
	&dev_attr_stereo_expansion.attr,
	&dev_attr_mono_downmix.attr,
	&dev_attr_mic_level_general.attr,
	&dev_attr_mic_level_call.attr,
	&dev_attr_debug_level.attr,
	&dev_attr_debug_info.attr,
	&dev_attr_debug_reg.attr,
	&dev_attr_debug_dump.attr,
	&dev_attr_change_delay.attr,
	&dev_attr_version.attr,
	NULL
};

// define attribute group
static struct attribute_group boeffla_sound_control_group = {
	.attrs = boeffla_sound_attributes,
};

// define control device
static struct miscdevice boeffla_sound_control_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "boeffla_sound",
};


/*****************************************/
// Driver init and exit functions
/*****************************************/

static int boeffla_sound_init(void)
{
	// register boeffla sound control device
	misc_register(&boeffla_sound_control_device);
	if (sysfs_create_group(&boeffla_sound_control_device.this_device->kobj,
				&boeffla_sound_control_group) < 0) {
		printk("Boeffla-sound: failed to create sys fs object.\n");
		return 0;
	}

	// Initialize boeffla sound master switch with OFF per default (will be set to correct
	// default value when we receive the codec pointer later - avoids startup boot loop)
	boeffla_sound = OFF;

	// initialize global variables and default debug level
	initialize_global_variables();

	// One-time only initialisations
	debug_level = DEBUG_DEFAULT;
	regdump_bank = 0;

	// Initialize delayed work for Eq reapplication
	INIT_DELAYED_WORK_DEFERRABLE(&apply_settings_work, apply_settings);

	// Print debug info
	printk("Boeffla-sound: engine version %s started\n", BOEFFLA_SOUND_VERSION);

	return 0;
}


static void boeffla_sound_exit(void)
{
	// remove boeffla sound control device
	sysfs_remove_group(&boeffla_sound_control_device.this_device->kobj,
                           &boeffla_sound_control_group);

	// Print debug info
	printk("Boeffla-sound: engine stopped\n");
}


/* define driver entry points */

module_init(boeffla_sound_init);
module_exit(boeffla_sound_exit);
