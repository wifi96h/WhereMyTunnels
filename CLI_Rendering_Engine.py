#!/usr/bin/python3
import re
#  /--------------------------------------------------------------------------------\
# |                       CLI RENDERING ENGINE - By Androsh7                         |
# |                    github.com/Androsh7/CLI_Rendering_Engine                      |
#  \--------------------------------------------------------------------------------/

class cli_render:
    start_line = 1 # y-offset to start printing on
    line_counter = start_line # keeps track of the current y-offset
    rendered_lines = [] # this stores all rendered lines
    prev_rendered_lines = []  # this stores all previously rendered lines

    # dictionary for cli color codes
    color = {
        "reset": "\033[0m",

        # standard colors
        "black": "\033[30m",
        "blue": "\033[34m",
        "green": "\033[32m",
        "cyan": "\033[36m",
        "red": "\033[31m",
        "purple": "\033[35m",
        "brown": "\033[33m",
        "yellow": "\033[1;33m",
        "white": "\033[1;37m",

        # light/dark colors
        "light_gray": "\033[33[37m",
        "dark_gray": "\033[33[1;30m",
        "light_blue": "\033[33[1;34m",
        "light_green": "\033[33[1;32m",
        "light_cyan": "\033[33[1;36m",
        "light_red": "\033[33[1;31m",
        "light_purple": "\033[33[1;35m",

        # highlights
        "black_highlight": "\033[40m",
        "red_highlight": "\033[41m",
        "green_highlight": "\033[42m",
        "yellow_highlight": "\033[43m",
        "blue_highlight": "\033[44m",
        "purple_highlight": "\033[45m",
        "cyan_highlight": "\033[46m",
        "white_highlight": "\033[47m",
    }

    @classmethod
    # clears the screen without moving the cursor
    def clear_screen(self):
        print("\033[2J", end="", sep="")
    
    @classmethod
    # sets the cursor position
    # NOTE: the starting position for the terminal is (0,1)
    def set_cursor(self, x_cord, y_cord):
        # check to ensure valid position
        if x_cord < 0 or y_cord < 0: 
            print("invalid cursor position from set_cursor to ({},{})".format(x_cord, y_cord))
            return 1
        print("\033[{};{}H".format(int(y_cord), int(x_cord)), end="", sep="")
    
    @classmethod
    # move cursor horizontally
    # WARNING NO INPUT VALIDATION
    def move_cursor_horz(self, x_change):
        if x_change > 0:
            print("\033[{}C".format(x_change), end="", sep="")
        elif x_change < 0:
            print("\033[{}D".format(x_change * -1), end="", sep="")
    
    @classmethod
    # move cursor vertically
    # WARNING NO INPUT VALIDATION
    def move_cursor_vert(self, y_change):
        if y_change > 0:
            print("\033[{}B".format(y_change), end="", sep="")
        elif y_change < 0:
            print("\033[{}A".format(y_change * -1), end="", sep="")

    @classmethod
    # prints a single line and increments the line_counter
    def print_line(self, print_line):
        self.set_cursor(0, self.line_counter)
        print(print_line, end="", sep="")

        # stores previously printed lines
        trimmed_line = re.sub("\033.*[a-zA-Z]", "", print_line) # this removes color formatting
        self.rendered_lines.append(trimmed_line)

        # grabs the length of the previous line, if one exists
        prev_len = 0
        if len(self.prev_rendered_lines) > self.line_counter:
            prev_len = self.prev_rendered_lines[self.line_counter]

        # pads the difference in length between the current line and the previous line
        if len(trimmed_line) < prev_len:
            padding = len(trimmed_line) - prev_len
            print(" " * padding, end="", sep="")
        
        print("\n", end="", sep="") # this prevents issues with lines not rendering

        self.line_counter += 1
    
    @classmethod
    # clear lines
    def clear_lines(self):
        while self.line_counter < len(self.prev_rendered_lines):
            padding = len(self.prev_rendered_lines[self.line_counter])
            print(" " * padding)

    @classmethod
    # reset class parameters
    def reset(self):
        self.prev_rendered_lines.clear()
        self.prev_rendered_lines = self.rendered_lines
        self.rendered_lines.clear()
        self.line_counter = self.start_line