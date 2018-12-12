####################################################
# Author : TALES 15-02-2003                        #
# File name: abc.tcl (Auto Botnick Changer)        #
# version script : v1                              #
# Script info : This script is for letting your bot#
#               change his nick when no active     #
#               users are talking in chan.Its      #
#               kinda away script for the bot or   #
#               not active of sleep when nobody is #
#               talking in chan.                   #
####################################################
# this is my first script hope you all like it and #
# dont be so hard :) if you got any questions you  #
#          can find me @ irc.tyson.nl              #
#         http://www.cb3rob.net/~tales/            #
####################################################
#     this script is made for eggdrop 1.6.13       #
#    use of this script is for your own risk!      #
####################################################
#  Note in config file ---> set keep-nick 0 <---   #
####################################################
# Credits : Barkerjr help with killtimer tnx man   #
#           Discover help with pubm i didnt know :)#
####################################################

# set botnck the nick of your bot
# example awake-bot , active-bot , talking-bot , [o][o] , yourbotnick
set botnck "awake-bot"

# set awaybotnck the nick of your bot when not active or away
# example sleep-bot , notactive-bot , silent-bot , [-][-] , yourbotnick[away]
set awaybotnck "sleep-bot"

# set nckchange-notactive-time how long will the but hold his botnick after time expire
# this number is now 30 min every number you place here is in min.
set nckchange-notactive-time 30

#code start here

bind pubm -|- * msg_nickchange

proc msg_nickchange {nick uhost hand chan args} {
 global botnck time-msg-loaded nckchange-notactive-time j
 set time-msg-loaded 1
 foreach j [timers] {
        if {[lindex $j 1] == "awaymynck"} { killtimer [lindex $j 2] }
      }
 set nckchange-notactive-time ${nckchange-notactive-time}
 timer ${nckchange-notactive-time} awaymynck
 putserv "nick ${botnck}"
}
 
if {![info exists {time-msg-loaded}]} {
 global time-msg-loaded nckchange-notactive-time
 set time-msg-loaded 1
 timer ${nckchange-notactive-time} awaymynck
}

proc awaymynck {} {
 global time-msg-loaded nckchange-notactive-time awaybotnck
 set time-msg-loaded 0
 putserv "nick ${awaybotnck}"
 timer ${nckchange-notactive-time} awaymynck
} 

#end of code



putlog "auto botnick changer script v1 By TALES is loaded ..... 15-02-2003"