/**
 *  Copyright 2020 Nortal AS
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package com.nortal.oidc.mitre.delegate;

import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.function.Function;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.Gender;
import org.pac4j.oauth.profile.facebook.FacebookProfile;
import org.pac4j.oauth.profile.google2.Google2Profile;
import org.pac4j.oauth.profile.linkedin2.LinkedIn2Profile;
import org.pac4j.oauth.profile.windowslive.WindowsLiveProfile;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.nortal.oidc.mitre.base.DefaultUserInfoCreator;

import lombok.Setter;

@Setter
public class Pac4jUserInfoCreator extends DefaultUserInfoCreator {
	private boolean prefixing = true;

	public DefaultUserInfo create(CommonProfile profile) {
		DefaultUserInfo info = new DefaultUserInfo();
		
		fromCommon(info, profile);
		
		if (info.getSub() == null) {
			throw new UsernameNotFoundException("Subject is null");
		}
		
		if (prefixing) {
			if (profile instanceof Google2Profile) {
				prefix(info, "GOOGLE");
			} else if (profile instanceof FacebookProfile) {
				prefix(info, "FACEBOOK");
			} else if (profile instanceof LinkedIn2Profile) {
				prefix(info, "LINKEDIN");
			} else if (profile instanceof WindowsLiveProfile) {
				prefix(info, "WINDOWSLIVE");
			}
		}
		
		return transform(info);
	}
	
	private static void prefix(DefaultUserInfo info, String p) {
		info.setSub(p + "::" + info.getSub());
	}

	public static void fromCommon(DefaultUserInfo info, CommonProfile profile) {
		set(info::setEmail, profile.getEmail());
		set(info::setFamilyName, profile.getFamilyName());

		Gender gender = profile.getGender();
		if (gender != Gender.UNSPECIFIED) {
			info.setGender(gender.name().toLowerCase());
		}

		set(info::setGivenName, profile.getFirstName());
		set(info::setLocale, profile.getLocale(), Locale::toLanguageTag);
		set(info::setName, profile.getDisplayName());
		set(info::setPicture, profile.getPictureUrl());
		set(info::setPreferredUsername, profile.getTypedId());
		set(info::setSub, profile.getEmail());
		
		if (info.getSub() == null && profile.getId() != null) {
			info.setSub(profile.getId());
		}
	}

	public static void fromGoogle(DefaultUserInfo info, Google2Profile profile) {
		set(info::setBirthdate, profile.getBirthday(),
				d -> DateTimeFormatter.ISO_DATE.format(d.toInstant()));
	}

	public static void fromFacebook(DefaultUserInfo info, FacebookProfile profile) {
		set(info::setBirthdate, profile.getBirthday(),
				d -> DateTimeFormatter.ISO_DATE.format(d.toInstant()));
	}

	private static <T, S> void set(Consumer<T> consumer, S object,
			Function<S, T> converter) {
		if (object != null) {
			consumer.accept(converter.apply(object));
		}
	}

	private static <T> void set(Consumer<T> consumer, T object) {
		if (object != null) {
			consumer.accept(object);
		}
	}
}
