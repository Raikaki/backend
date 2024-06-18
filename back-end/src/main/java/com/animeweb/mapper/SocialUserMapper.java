package com.animeweb.mapper;

import com.animeweb.dto.user.SocialUser;
import com.animeweb.entities.User;

public class SocialUserMapper {
    public static User mapToEntity(SocialUser socialUser) {
        return new User( socialUser.getUserName(),
                socialUser.getAvatarPicture(),
                socialUser.getPassword(),
                socialUser.getEmail(),
                socialUser.getFullName(),
                socialUser.getPhone(),
                socialUser.getUserType(),
                socialUser.getCreatedAt(),
                socialUser.getUpdatedAt(),
                socialUser.getDeletedAt(),
                socialUser.getStatus(),
                socialUser.getExternalId(),
                socialUser.getViews(),
                socialUser.getRates(),
                socialUser.getFollows()
        );
    }
}
