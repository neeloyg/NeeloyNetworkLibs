package com.neeloy.networklibs;

/**
 * Created by NeeloyG on 02-05-2017.
 */

public enum  Language{

//        German	de	values-de/strings.xml
//        Chinese	zh	values-zh/strings.xml
//        Czech	cs	values-cs/strings.xml
//        Dutch	nl	values-nl/strings.xml
//        French	fr	values-fr/strings.xml
//        Italian	it	values-it/strings.xml
//        Japanese	ja	values-ja/strings.xml
//        Korean	ko	values-ko/strings.xml
//        Polish	pl	values-pl/strings.xml
//        Russian	ru	values-ru/strings.xml
//        Spanish	es	values-es/strings.xml
//        Arabic	ar	values-ar/strings.xml
//        Bulgarian	bg	values-bg/strings.xml
//        Catalan	ca	values-ca/strings.xml
//        Croatian	hr	values-hr/strings.xml
//        Danish	da	values-da/strings.xml
//        Finnish	fi	values-fi/strings.xml
//        Greek	el	values-el/strings.xml
//        Hebrew	iw	values-iw/strings.xml
//        Hindi	hi	values-hi/strings.xml
//        Hungarian	hu	values-hu/strings.xml
//        Indonesian	in	values-in/strings.xml
//        Latvian	lv	values-lv/strings.xml
//        Lithuanian	lt	values-lt/strings.xml
//        Norwegian	nb	values-nb/strings.xml
//        Portuguese	pt	values-pt/strings.xml
//        Romanian	ro	values-ro/strings.xml
//        Serbian	sr	values-sr/strings.xml
//        Slovak	sk	values-sk/strings.xml
//        Slovenian	sl	values-sl/strings.xml
//        Swedish	sv	values-sv/strings.xml
//        Tagalog	tl	values-tl/strings.xml
//        Thai	th	values-th/strings.xml
//        Turkish	tr	values-tr/strings.xml
//        Ukrainian	uk	values-uk/strings.xml
//        Vietnamese	vi	values-vi/strings.xml

    hi,
    en,
    ar;


    public String value() {
        return this.name();
    }

    public static Language fromValue(String v) {
        return valueOf(v);
    }

}
