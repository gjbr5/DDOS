TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
SOURCES += \
        ifctl.cpp \
        main.cpp \
        packet_filter.cpp

HEADERS += \
    ifctl.h \
    include.h \
    packet_filter.h \
    protocol_structure.h
