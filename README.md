Anarchy Online Historical Preservation Society
==============================================

This program parses a packet capture file in the pcapng format, like
those produced by wireshark, and extracts any data important for the
historical preservation of Funcom's MMORPG Anarchy Online.

The overarching goal of this project is to preserve the game in its
current state so that it may be played long after the official servers
have ceased operation.  There has been great effort put into making
historical games playable in their original form, such as the MESS and
MAME projects.  MMORPGs present an extra challenge, as not only is the
game logic implemented in a server that is rarely publicly available,
but the a large part of the game's content is also held on the server
and transmitted to the user on request.

This project focuses on the second challenge, preserving the game's
content.

Compiling
---------

I only tested this on VS2010, but since I intend to run it server-side
I will port it to mono as soon as I can.

Get (some of) the dependencies using
    git submodule init
    git submodule update

Get [ZLib.Net](http://www.componentace.com/zlib_.NET.htm) and place it
in the lib directory.

Open AOCapture.sln

Open an issue if I forgot a step lol


Current status and TODO list
----------------------------

This program parses and reassembles TCP packets into a stream, and
parses AO packets. (in part thanks to the PcapngFile and AOtomation
libraries)

It doesn't do anything more than that yet.  It needs to:

* extract the data into a database.

Other modules will need to:

* deduplicate the data, merge conversation graphs, infer spawn
  locations and movement patterns, infer shop price distributions

* bundle winpcap along with an uploader and nice UI, since we don't
  want to require that users run wireshark.  

* a web front-end needs to receive the capture files.

* It would be a Really Good Idea to discard authentication data before
  file upload, but that would require having a whole parser on the
  client side.

It is my hope that the program developed in the deduplication and
merging phase of the project will be reusable for other MMORPGs.
Ideally someone would do this far earlier in a game's lifetime. (AO is
13 years old!)

While we will never be able to recreate the original experience of
playing an MMORPG, since much of it is driven by the players, I hope
to at least preserve the worlds in which we played.  If you want to
preserve the rest, you'd need MMO journalists and historians.

