/*
	Copyright 2015 bigbiff/Dees_Troy TeamWin
	This file is part of TWRP/TeamWin Recovery Project.

	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

// console.cpp - GUIConsole object

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <string>

extern "C" {
#include "../twcommon.h"
}
#include "twmsg.h"
#include "objects.hpp"

#define GUI_CONSOLE_BUFFER_SIZE 512

struct InitMutex
{
	InitMutex() { pthread_mutex_init(&console_lock, NULL); }
} initMutex;

void GUIMsg::internal_gui_print(const char *color, char *buf)
{
	// make sure to flush any outstanding messages first to preserve order of outputs
	GUIConsole::Translate_Now();

	fputs(buf, stdout);
	if (ors_file) {
		fprintf(ors_file, "%s", buf);
		fflush(ors_file);
	}

	char *start, *next;

	if (buf[0] == '\n' && strlen(buf) < 2) {
		// This prevents the double lines bug seen in the console during zip installs
		return;
	}

	pthread_mutex_lock(&console_lock);
	for (start = next = buf; *next != '\0';)
	{
		if (*next == '\n')
		{
			*next = '\0';
			gConsole.push_back(start);
			gConsoleColor.push_back(color);

			start = ++next;
		}
		else
			++next;
	}

	// The text after last \n (or whole string if there is no \n)
	if (*start) {
		gConsole.push_back(start);
		gConsoleColor.push_back(color);
	}
	pthread_mutex_unlock(&console_lock);
}

extern "C" void gui_print(const char *fmt, ...)
{
	char buf[GUI_CONSOLE_BUFFER_SIZE];		// We're going to limit a single request to 512 bytes

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, GUI_CONSOLE_BUFFER_SIZE, fmt, ap);
	va_end(ap);

	internal_gui_print("normal", buf);
}

extern "C" void gui_print_color(const char *color, const char *fmt, ...)
{
	char buf[GUI_CONSOLE_BUFFER_SIZE];		// We're going to limit a single request to 512 bytes

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, GUI_CONSOLE_BUFFER_SIZE, fmt, ap);
	va_end(ap);

	internal_gui_print(color, buf);
}

extern "C" void gui_set_FILE(FILE* f)
{
	ors_file = f;
}

void GUIMsg::gui_msg(const char* text)
{
	if (text) {
		Message msg = Msg(text);
		gui_msg(msg);
	}
}

void GUIMsg::gui_warn(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kWarning, text);
		gui_msg(msg);
	}
}

void GUIMsg::gui_process(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kProcess, text);
		gui_msg(msg);
	}
}

void GUIMsg::gui_err(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kError, text);
		gui_msg(msg);
	}
}

void GUIMsg::gui_highlight(const char* text)
{
	if (text) {
		Message msg = Msg(msg::kHighlight, text);
		gui_msg(msg);
	}
}

void GUIMsg::gui_msg(Message msg)
{
	std::string output = msg;
	output += "\n";
	fputs(output.c_str(), stdout);
	if (ors_file) {
		fprintf(ors_file, "%s", output.c_str());
		fflush(ors_file);
	}
	pthread_mutex_lock(&console_lock);
	gMessages.push_back(msg);
	pthread_mutex_unlock(&console_lock);
}