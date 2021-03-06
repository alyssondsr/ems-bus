#!/bin/bash
#
# Autor: Everton de Vargas Agilar
# Data: 08/06/2016
#
# Objective: To generate the bus release in the main Linux distros
#
# How to use: 
#
#    $ ./release.sh
#
#
#
#
#
## Software modification history:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 28/11/2016  Everton Agilar     Release inicial do script de release
# 05/03/2017  Everton Agilar     Improve release to deb and rpm
# 06/07/2017  Everton Agilar     New: --skip_build
# 23/09/2017  Everton Agilar     New: --push
# 28/09/2017  Everton Agilar     New: --clean
#
#
#
#
#
########################################################################################################

# Parameters
WORKING_DIR=$(pwd)
RELEASE_PATH=$WORKING_DIR
GIT_RELEASE_REPO=https://github.com/erlangms/releases
BUILD_RPM_FLAG="$( rpmbuild --version > /dev/null 2>&1 && echo 'true' || echo 'false')"  
BUILD_DEB_FLAG="$( dpkg-deb --version > /dev/null 2>&1 && echo 'true' || echo 'false')"  
SKIP_BUILD="true"
PUSH="false"

# Identify the linux distribution: ubuntu, debian, centos
LINUX_DISTRO=$(awk -F"=" '{ if ($1 == "ID"){ 
								gsub("\"", "", $2);  print $2 
							} 
						  }' /etc/os-release)

# Get linux description
LINUX_DESCRIPTION=$(awk -F"=" '{ if ($1 == "PRETTY_NAME"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)


LINUX_VERSION_ID=$(awk -F"=" '{ if ($1 == "VERSION_ID"){ 
									gsub("\"", "", $2);  print $2 
								 } 
							   }'  /etc/os-release)


# Imprime uma mensagem e termina o script
# Parâmetros:
#  $1  - Mensagem que será impressa 
die () {
    echo $1
    exit 1
}

config_release_path(){
	if [ "$PUSH" = "true" ]; then
		# Sets the RELEASE_PATH variable with the path of the releases folder
		# If the folder does not exist, then you must first download
		if cd $WORKING_DIR/../../releases 2> /dev/null; then
			RELEASE_PATH=$(cd $WORKING_DIR/../../releases/ && pwd)
		else
			echo "First, you need to download the release folder..."
			cd ../../
			git clone https://github.com/erlangms/releases
			cd $WORKING_DIR
			RELEASE_PATH=$(cd $WORKING_DIR/../../releases/ && pwd)
		fi
	else
		RELEASE_PATH="/tmp/erlangms_releases_$$"
		mkdir -p $RELEASE_PATH
	fi
	echo "Setting release path to $RELEASE_PATH."
}

# ***** Clean ******
clean(){
	echo "Clean release build..."
	cd $WORKING_DIR
	rm -Rf ems-bus
	rm -Rf ems_bus
	rm -f *.tar.gz
	rm -f *.tar
	
	# Loop pelas pastas de templates dos pacotes rpm
	for SKEL_RPM_PACKAGE in `find ./rpm/* -maxdepth 0 -type d`; do
		# remove old
		rm -Rf $SKEL_RPM_PACKAGE/BUILD
		rm -Rf $SKEL_RPM_PACKAGE/SOURCES
		rm -Rf $SKEL_RPM_PACKAGE/BUILDROOT
		rm -Rf $SKEL_RPM_PACKAGE/RPMS

		# create new
		mkdir -p $SKEL_RPM_PACKAGE/BUILD
		mkdir -p $SKEL_RPM_PACKAGE/SOURCES
		mkdir -p $SKEL_RPM_PACKAGE/BUILDROOT
		mkdir -p $SKEL_RPM_PACKAGE/RPMS
	done
	
	# Loop pelas pastas de templates dos pacotes deb
	for SKEL_DEB_PACKAGE in `find ./deb/* -maxdepth 0 -type d`; do
		# remove old
		rm -Rf $SKEL_DEB_PACKAGE/usr
		rm -Rf $SKEL_DEB_PACKAGE/etc
		rm -f $SKEL_DEB_PACKAGE/DEBIAN/postinst
		rm -f $SKEL_DEB_PACKAGE/DEBIAN/postrm
		rm -f $SKEL_DEB_PACKAGE/DEBIAN/preinst
		rm -f $SKEL_DEB_PACKAGE/DEBIAN/prerm
		rm -f $SKEL_DEB_PACKAGE/*.deb
		
		# create new
		mkdir -p $SKEL_DEB_PACKAGE/usr
		mkdir -p $SKEL_DEB_PACKAGE/etc
	done
}


# show help 
help(){
	echo "release.sh tool"
	echo "How to use: ./release.sh"
	echo
	echo "Additional parameters:"
	echo "  --skip-build     -> skip build with rebar. Default is true."
	echo "  --push           -> push release to repository. Default is false."
	echo "  --clean          -> clean build release."
	exit 1
}


# send the generated package to the releases folder (if the releases folder exists)
# $1 = PACKAGE_FILE
# $2 = PACKAGE_NAME
send_build_repo(){
	cd $WORKING_DIR
	PACKAGE_FILE=$1
	PACKAGE_NAME=$2
	if [ -d $RELEASE_PATH ]; then
		rm -f $RELEASE_PATH/$VERSION_RELEASE/$PACKAGE_NAME
		mkdir -p $RELEASE_PATH/$VERSION_RELEASE/
		cp $PACKAGE_FILE  $RELEASE_PATH/$VERSION_RELEASE/
	fi
}	

# send the generated package to git
push_release(){
	if [ "$PUSH" = "true" ]; then
		cd $RELEASE_PATH
		echo "$VERSION_RELEASE" > setup/current_version
		git add $VERSION_RELEASE >> /dev/null
		git add setup/current_version >> /dev/null
		git commit -am "New release $VERSION_RELEASE" >> /dev/null
		echo "Sending package $PACKAGE_NAME to $GIT_RELEASE_REPO..."
		git pull --no-edit
		git push
	fi
}

# make release for each distro
make_release(){
	cd $WORKING_DIR

	# Get the build version of the bus that is in the file src/ems_bus.app.src
	VERSION_RELEASE=$(cat ../src/ems_bus.app.src | sed -rn  's/^.*\{vsn.*([0-9]{1,2}\.[0-9]{1,2}.[0-9]{1,2}).*$/\1/p')
	[ -z "$VERSION_RELEASE" ] && die "Could not get version to be generated in rebar.config"
	echo "Please wait, generating the release $VERSION_RELEASE of the ems-bus, this may take a while!"


	# ########## Recompile the project before generating the release ########## 
	
	cd ..
	if [ "$SKIP_BUILD" = "false" ]; then
		echo 'Recompiling the fonts with rebar...'
		./build.sh
	fi


	# rebar is installed
	#if ! rebar --version 2> /dev/null ]; then
	#	if [ "$LINUX_DISTRO" = "ubuntu" ]; then
	#		echo "O software de build rebar não está instalado mas eu posso instalar para você!"
	#		sudo apt-get install rebar
	#	fi
	#fi


	# ******** Gera o release na pasta rel *********
	echo 'Generating release with rebar now...'
	cd rel
	../tools/rebar/rebar generate || die 'Failed to generate release with rebar compile generate!'

	# Esta lib dá erro no com "tools/rebar/rebar compile generate", portando é copiado manualmente
	if [ -d ems_bus/lib/sd_notify ]; then
		mkdir ems_bus/lib/sd_notify
		cp -r ../deps/sd_notify/ebin ems_bus/lib/sd_notify
		cp -r ../deps/sd_notify/priv ems_bus/lib/sd_notify
	fi
	
	mv ems_bus ems-bus
	mv ems-bus/bin/ems_bus ems-bus/bin/ems-bus


	#Creates the symlink of the priv folder for the project lib ems_bus-$VERSION/priv
	cd ems-bus
	ln -sf lib/ems_bus-$VERSION_RELEASE/priv/ priv || die "The symbolic priv link could not be created for lib/ems_bus-$VERSION_RELEASE/priv!"
	# Faz algumas limpezas para não ir lixo no pacote
	rm -Rf log || die 'Could not remove log folder in cleanup!'
	rm -rf priv/db || die 'Unable to remove db folder in cleanup!'
	cd ..


	# ####### Create the package ems-bus-x.x.x.tar.gz #######

	# Create the package file gz
	echo "Creating package ems-bus-$VERSION_RELEASE.gz..."
	tar -czf ems-bus-$VERSION_RELEASE.tar.gz ems-bus/ &

	# build rpm packages
	if [ "$BUILD_RPM_FLAG" = "true" ]; then

		# ####### Create the rpm packages for each distro ############

		for SKEL_RPM_PACKAGE in `find ./rpm/* -maxdepth 0 -type d`; do
			echo "Creating rpm package for template $SKEL_RPM_PACKAGE..."

			SKEL_PACKAGE_SOURCES="$SKEL_RPM_PACKAGE/SOURCES"
			VERSION_PACK=$VERSION_RELEASE
			# Updates the version in the file SPEC/emsbus.spec
			sed -ri "s/Version: .*$/Version: $VERSION_PACK/"  $SKEL_RPM_PACKAGE/SPECS/emsbus.spec
			RELEASE_PACK=$(grep 'Release:' $SKEL_RPM_PACKAGE/SPECS/emsbus.spec | cut -d":" -f2 | tr " " "\0")
			PACKAGE_NAME=ems-bus-$VERSION_RELEASE-$RELEASE_PACK.x86_64.rpm
			PACKAGE_FILE=$SKEL_RPM_PACKAGE/RPMS/x86_64/$PACKAGE_NAME
			
			# Creates the folder where the sources will be placed 
			mkdir -p $SKEL_PACKAGE_SOURCES || die "Could not create folder $SKEL_PACKAGE_SOURCES!"

			# Gera a estrutura /usr/lib/ems-bus
			rm -Rf $SKEL_PACKAGE_SOURCES/usr/lib/ems-bus || die "Could not remove folder $SKEL_RPM_PACKAGE/usr/lib/ems-bus!" 
			mkdir -p $SKEL_PACKAGE_SOURCES/usr/lib
			cp -R ems-bus $SKEL_PACKAGE_SOURCES/usr/lib/ems-bus || die "Could not copy folder ems-bus to $SKEL_RPM_PACKAGE/usr/lib!"

			rm -Rf $SKEL_PACKAGE_SOURCES/etc || die "Could not remove folder $SKEL_RPM_PACKAGE/etc!" 

			# Gera a estrutura /etc/ems-bus
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/ems-bus || die "Could not create folder $SKEL_RPM_PACKAGE/etc/ems-bus!" 
			ln -s /usr/lib/ems-bus/priv/catalog $SKEL_PACKAGE_SOURCES/etc/ems-bus/catalog
			ln -s /usr/lib/ems-bus/priv/conf $SKEL_PACKAGE_SOURCES/etc/ems-bus/conf
			ln -s /usr/lib/ems-bus/priv/csv $SKEL_PACKAGE_SOURCES/etc/ems-bus/csv
			ln -s /usr/lib/ems-bus/priv/ssl $SKEL_PACKAGE_SOURCES/etc/ems-bus/ssl
			ln -s /usr/lib/ems-bus/priv/schema $SKEL_PACKAGE_SOURCES/etc/ems-bus/schema
			ln -s /usr/lib/ems-bus/priv/systemd $SKEL_PACKAGE_SOURCES/etc/ems-bus/systemd
			ln -s /usr/lib/ems-bus/priv/firewalld $SKEL_PACKAGE_SOURCES/etc/ems-bus/firewalld
			
			# Gera a estrutura /etc/systemd/system
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/systemd/system
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/systemd/system/ems-bus.service.d
			ln -s /usr/lib/ems-bus/priv/systemd/ems-bus.service $SKEL_PACKAGE_SOURCES/etc/systemd/system/ems-bus.service || die 'Could not create symbolic link ems-bus.service!' 
			ln -s /usr/lib/ems-bus/priv/systemd/ems-bus.service.d/limits.conf $SKEL_PACKAGE_SOURCES/etc/systemd/system/ems-bus.service.d/limits.conf || die 'Could not create symbolic link ems-bus.service.d/limits.conf!'

			# Gera a estrutura /etc/firewalld
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/firewalld/services
			ln -s /usr/lib/ems-bus/priv/firewalld/ems-bus.xml $SKEL_PACKAGE_SOURCES/etc/firewalld/services/ems-bus.xml || die "Could not create symbolic link $SKEL_RPM_PACKAGE/etc/firewalld/services/ems-bus.xml!" 

			# Gera a estrutura /etc/sudoers.d
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/sudoers.d
			ln -s /usr/lib/ems-bus/priv/sudoers.d/ems-bus.sudoers $SKEL_PACKAGE_SOURCES/etc/sudoers.d/ems-bus.sudoers || die "Could not create symbolic link $SKEL_RPM_PACKAGE/etc/sudoers.d/ems-bus!" 

			# Log -> /var/log/ems-bus
			#ln -s /var/log/ems-bus $SKEL_PACKAGE_SOURCES/usr/lib/ems-bus/priv/log

			#echo "Generate $SKEL_PACKAGE_SOURCES/ems-bus-$VERSION_PACK.tar.gz from $SKEL_PACKAGE_SOURCES"
			tar -czvf  ems-bus-$VERSION_PACK.tar.gz *
			
			echo "rpm build with rpmbuild..."
			cd $SKEL_RPM_PACKAGE
			rpmbuild -bb SPECS/emsbus.spec

			send_build_repo $PACKAGE_FILE $PACKAGE_NAME
		done
		
	# build deb packages	
	elif [ "$BUILD_DEB_FLAG" = "true" ]; then
		
		# ####### Create the deb packages for each distro ############

		for SKEL_DEB_PACKAGE in `find ./deb/* -maxdepth 0 -type d`; do
			echo "Creating deb package for template $SKEL_DEB_PACKAGE..."
			
			VERSION_PACK=$VERSION_RELEASE
			DEB_CONTROL_FILE=$SKEL_DEB_PACKAGE/DEBIAN/control
			SKEL_PACKAGE_SOURCES=$SKEL_DEB_PACKAGE
			# Updates the version in the file SPEC/emsbus.spec
			sed -ri "s/Version: .{6}(.*$)/Version: $VERSION_RELEASE\1/" $DEB_CONTROL_FILE
			RELEASE_PACK=$(grep 'Version' $DEB_CONTROL_FILE | cut -d'-' -f2-)	
			PACKAGE_NAME=ems-bus-$VERSION_RELEASE-$RELEASE_PACK.x86_64.deb
			PACKAGE_FILE=$SKEL_DEB_PACKAGE/$PACKAGE_NAME
			
			# Gera a estrutura /usr/lib/ems-bus
			rm -Rf $SKEL_DEB_PACKAGE/usr/lib/ems-bus || die "Could not remove folder $SKEL_DEB_PACKAGE/usr/lib/ems-bus!" 
			mkdir -p $SKEL_DEB_PACKAGE/usr/lib
			cp -R ems-bus $SKEL_DEB_PACKAGE/usr/lib/ems-bus || die "Could not copy ems-bus folder to $SKEL_DEB_PACKAGE/usr/lib!"

			rm -Rf $SKEL_DEB_PACKAGE/etc || die "Could not remove folder $SKEL_DEB_PACKAGE/etc!" 

			# Gera a estrutura /etc/ems-bus
			mkdir -p $SKEL_DEB_PACKAGE/etc/ems-bus || die "Could not create folder $SKEL_DEB_PACKAGE/etc/ems-bus!" 
			ln -s /usr/lib/ems-bus/priv/catalog $SKEL_DEB_PACKAGE/etc/ems-bus/catalog
			ln -s /usr/lib/ems-bus/priv/conf $SKEL_DEB_PACKAGE/etc/ems-bus/conf
			ln -s /usr/lib/ems-bus/priv/csv $SKEL_DEB_PACKAGE/etc/ems-bus/csv
			ln -s /usr/lib/ems-bus/priv/ssl $SKEL_DEB_PACKAGE/etc/ems-bus/ssl
			ln -s /usr/lib/ems-bus/priv/schema $SKEL_DEB_PACKAGE/etc/ems-bus/schema
			ln -s /usr/lib/ems-bus/priv/systemd $SKEL_DEB_PACKAGE/etc/ems-bus/systemd
			
			# Gera a estrutura /etc/systemd/system
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/systemd/system
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/systemd/system/ems-bus.service.d
			ln -s /usr/lib/ems-bus/priv/systemd/ems-bus.service $SKEL_PACKAGE_SOURCES/etc/systemd/system/ems-bus.service || die 'Could not create symbolic link ems-bus.service!'
			ln -s /usr/lib/ems-bus/priv/systemd/ems-bus.service.d/limits.conf $SKEL_PACKAGE_SOURCES/etc/systemd/system/ems-bus.service.d/limits.conf || die 'Could not create symbolic link ems-bus.service.d/limits.conf!'

			# Gera a estrutura /etc/sudoers.d
			mkdir -p $SKEL_PACKAGE_SOURCES/etc/sudoers.d
			ln -s /usr/lib/ems-bus/priv/sudoers.d/ems-bus.sudoers $SKEL_PACKAGE_SOURCES/etc/sudoers.d/ems-bus.sudoers || die "Could not create symbolic link $SKEL_RPM_PACKAGE/etc/sudoers.d/ems-bus!" 

			# Log -> /var/log/ems-bus
			#ln -s /var/log/ems-bus $SKEL_DEB_PACKAGE/usr/lib/ems-bus/priv/log
			
			# Copia os scripts padrão para o pacote
			cp -f deb/postinst $SKEL_DEB_PACKAGE/DEBIAN
			cp -f deb/postrm $SKEL_DEB_PACKAGE/DEBIAN
			cp -f deb/preinst $SKEL_DEB_PACKAGE/DEBIAN
			cp -f deb/prerm $SKEL_DEB_PACKAGE/DEBIAN
			
			echo "deb build with dpkg-deb..."
			dpkg-deb -b $SKEL_DEB_PACKAGE $PACKAGE_FILE || die "Failed to generate package $SKEL_DEB_PACKAGE com dpkg-deb!"

			send_build_repo $PACKAGE_FILE $PACKAGE_NAME
		done
	fi
}


# *************** main ***************

echo "Start erlangms release tool ( Date: $(date '+%d/%m/%Y %H:%M:%S')  Distro: $LINUX_DISTRO )"
echo "Linux: $LINUX_DESCRIPTION  Version: $LINUX_VERSION_ID"

[ "$BUILD_RPM_FLAG" = "true" ] && echo "Build rpm packages with rpmbuild available."
[ "$BUILD_DEB_FLAG" = "true" ] && echo "Build deb packages with dpkg-deb available."


# Read command line parameters
for P in $*; do
	if [[ "$P" =~ ^--.+$ ]]; then
		if [ "$P" = "--help" ]; then
			help
		elif [[ "$P" = "--clean" ]]; then
			clean
			exit 1
		elif [[ "$P" =~ --skip[_-]build ]]; then
			echo "Skip build ems-bus enabled..."
			SKIP_BUILD="true"
		elif [[ "$P" =~ --push ]]; then
			echo "Push release after build to repository..."
			PUSH="true"
		else
			echo "Invalid parameter: $P"
			help
		fi
	else
		echo "Invalid parameter: $P"
		help
	fi
done


# check remove link to fix Unable to generate spec: read file info
if [ -L /usr/lib/erlang/man ]; then
	echo "Preciso de permissão para remover o link /usr/lib/erlang/man (fix Unable to generate spec: read file info)"
	sudo rm  /usr/lib/erlang/man
fi	

rm -f ../priv/scripts/*.tar
clean
config_release_path
make_release
push_release
clean
cd $WORKING_DIR
echo "Ok!"

