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

#!/bin/bash
source config.sh

echo "applying patches for dionaea.conf and ihandlers.py and backup the original files"
patch -b -d ${DIONAEA_ROOT}etc/dionaea < dionaea.conf.diff
patch -b -d ${DIONAEA_ROOT}lib/dionaea/python/dionaea < ihandlers.py.diff

echo "copy jsonfeeds.py (and ssl folder if it exists)"
cp jsonfeeds.py ${DIONAEA_ROOT}lib/dionaea/python/dionaea

if [ -d "ssl" ]; then
	cp -r ssl $SSL_ROOT
fi
