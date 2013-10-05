    #********************************************************************************
    #*
    #* TraCINg (Sensor Part) - prepares Dionaea data for TraCINg server
    #* Copyright (C) 2013 	Matthias Gazzari, Annemarie Mattmann, Andre Mougoui,
    #*						André Wolski
    #* 
    #* This program is free software; you can redistribute it and/or
    #* modify it under the terms of the GNU General Public License
    #* as published by the Free Software Foundation; either version 2
    #* of the License, or (at your option) any later version.
    #* 
    #* This program is distributed in the hope that it will be useful,
    #* but WITHOUT ANY WARRANTY; without even the implied warranty of
    #* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    #* GNU General Public License for more details.
    #* 
    #* You should have received a copy of the GNU General Public License
    #* along with this program; if not, write to the Free Software
    #* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
    #* 
    #* contact	matthias.gazzari@stud.tu-darmstadt.de, mattmann@stud.tu-darmstadt.de,
    #* 			andre.wolski@stud.tu-darmstadt.de
    #*
    #********************************************************************************
    #*
    #* This code is based on code from the Dionaea project, see
    #* http://dionaea.carnivore.it/
    #* which is also licensed under GNU General Public License v2.
    #*
    #********************************************************************************

## Introduction

*jsonfeeds* is an ihandler for [dionaea](http://dionaea.carnivore.it/).

The purpose of *jsonfeeds* is to log events provided by dionaea in a JSON format via HTTP-POST to an HTTPS server. This module is developed for the [TraCINg](https://github.com/Cyber-Incident-Monitor/TraCINg-Server) project but could be used to post to a custom server.


## Requirements

### dionaea

Of course *jsonfeeds* requires dionaea.

You can use the [complete compiling instructions](http://dionaea.carnivore.it/#compiling), below the compiling instructions is also a section for packages on common distributions. If you want to use dionaea on Arch Linux ARM you can find the packages on https://github.com/Cyber-Incident-Monitor/PKGBUILDs.


### python

Like all dionaea ihandlers *jsonfeeds* is written in python3 (which is already required by dionaea).

Additionally, *jsonfeeds* depends on [python-requests](http://python-requests.org/), please read their installation guide or search for a package from your distribution.


## Configuration

Like other ihandlers for dionaea *jsonfeeds* reads its configuration from the dionaea configfile, wich can be found in most installations in /opt/dionaea/etc/dionaea/dionaea.conf

A sample configuration is provided in dionaea.conf.diff (as a diff to the default dionaea.conf).

## Installation

### manual

  - copy jsonfeeds.py to /opt/dionaea/lib/dionaea/python/dionaea
  - patch config into dionaea.conf
  - patch ihandler into /opt/dionaea/lib/dionaea/python/dionaea/ihandlers.py 
  - if you are using client certificates copy the certificate and key into the location you provided in the config

### automatic

The automatic scripts should work if you are using a default installation of dionaea:

  - check (and edit) the paths provided in config.sh
  - check (and edit) the config in dionaea.conf.diff
  - run install.sh

