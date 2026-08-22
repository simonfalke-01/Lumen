if(UNIX)
    if(${SUNSHINE_CONFIGURE_HOMEBREW})
        configure_file(packaging/sunshine.rb lumen.rb @ONLY)
    endif()
endif()

if(APPLE)
    if(${SUNSHINE_CONFIGURE_PORTFILE})
        configure_file(packaging/macos/Portfile Portfile @ONLY)
    endif()
elseif(UNIX)
    # Template filenames retain the upstream application ID only as a source-tree
    # compatibility detail. Configured package identities always use PROJECT_FQDN.
    set(LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN "${PROJECT_LEGACY_FQDN}")

    # configure the .desktop file
    set(SUNSHINE_DESKTOP_ICON "${PROJECT_FQDN}")
    if(${SUNSHINE_BUILD_APPIMAGE})
        configure_file(packaging/linux/AppImage/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.desktop ${PROJECT_FQDN}.desktop @ONLY)
    elseif(${SUNSHINE_BUILD_FLATPAK})
        configure_file(packaging/linux/flatpak/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.desktop ${PROJECT_FQDN}.desktop @ONLY)
    else()
        configure_file(packaging/linux/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.desktop ${PROJECT_FQDN}.desktop @ONLY)
        configure_file(packaging/linux/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.terminal.desktop ${PROJECT_FQDN}.terminal.desktop @ONLY)
    endif()

    # configure metadata file
    configure_file(packaging/linux/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.metainfo.xml ${PROJECT_FQDN}.metainfo.xml @ONLY)

    # configure service
    configure_file(packaging/linux/app-${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.service.in app-${PROJECT_FQDN}.service @ONLY)

    # configure kwin desktop permission file
    if (${SUNSHINE_ENABLE_KWIN})
        configure_file(packaging/linux/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.kwin.desktop.in ${PROJECT_FQDN}.kwin.desktop @ONLY)
    endif()

    # configure the arch linux pkgbuild
    if(${SUNSHINE_CONFIGURE_PKGBUILD})
        string(REPLACE "-" "." LUMEN_ARCH_VERSION "${PROJECT_VERSION}")
        configure_file(packaging/linux/Arch/PKGBUILD PKGBUILD @ONLY)
        configure_file(packaging/linux/Arch/sunshine.install lumen.install @ONLY)
        unset(LUMEN_ARCH_VERSION)
    endif()

    # configure the flatpak manifest
    if(${SUNSHINE_CONFIGURE_FLATPAK_MAN})
        configure_file(packaging/linux/flatpak/${LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN}.yml ${PROJECT_FQDN}.yml @ONLY)
        file(COPY packaging/linux/flatpak/deps/ DESTINATION ${CMAKE_BINARY_DIR})
        file(COPY packaging/linux/flatpak/modules DESTINATION ${CMAKE_BINARY_DIR})
        file(COPY generated-sources.json DESTINATION ${CMAKE_BINARY_DIR})
        file(COPY package-lock.json DESTINATION ${CMAKE_BINARY_DIR})
    endif()

    unset(LUMEN_LEGACY_PACKAGING_TEMPLATE_FQDN)
endif()

# return if configure only is set
if(${SUNSHINE_CONFIGURE_ONLY})
    # message
    message(STATUS "SUNSHINE_CONFIGURE_ONLY: ON, exiting...")
    set(END_BUILD ON)
else()
    set(END_BUILD OFF)
endif()
