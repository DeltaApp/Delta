import { Document, Types } from "mongoose";
import { env } from "../../constants.js";
import { generateAuthToken } from "../../functions/token.js";
import { generateSnowflakeID } from "../../functions/uid.js";
import { IGuild, IUser } from "../../interfaces.js";
import { User } from "../schema/user.js";
import { Guild } from "../schema/guild.js";

export const getUsers = async ({
  ids,
  usernames,
}: {
  ids?: string[];
  usernames?: string[];
}): Promise<(IUser & Document)[] | null> => {
  let users: (IUser & Document)[] | null = null;
  if (ids) {
    users = await User.find({ id: { $in: ids } });
  } else if (usernames) {
    users = await User.find({ username: { $in: usernames } });
  } else return null;
  return users;
};

export const getUserById = async (
  userId: string
): Promise<(IUser & Document<Types.ObjectId>) | null> => {
  const user = await User.findOne<IUser & Document<Types.ObjectId>>({
    id: userId,
  });
  if (!user) return null;
  return await user.populate({
    path: "guilds",
    populate: "channels",
  });
};

export const getUserByToken = async (
  token: string
): Promise<(IUser & Document) | null> => {
  const user = await User.findOne({ token: token });
  if (!user) return null;
  return user;
};

export const createUser = async (
  data: Omit<
    IUser,
    | "id"
    | "disabled"
    | "deleted"
    | "bot"
    | "system"
    | "token"
    | "guilds"
    | "avatar"
  > & { hashedPassword: string }
): Promise<(IUser & Document) | null> => {
  try {
    const defaultGuildID = "67adde6604bd4e70d418a65a";
    const id = generateSnowflakeID("u");
    const token = await generateAuthToken(
      id,
      data.handle,
      data.password,
      data.hashedPassword
    );

    const user = new User<Omit<IUser, "guilds"> & { guilds: string[] }>({
      id,
      username: data.username,
      handle: data.handle,
      avatar: `https://${env.API_ORIGIN}/images/delta-${parseInt(id.slice(1)) % 5
        }.png`,
      roles: 0,
      password: data.hashedPassword,
      disabled: false,
      deleted: false,
      bot: false,
      system: false,
      token,
      guilds: [defaultGuildID]
    });
    
    await user.save();
    await Guild.findOneAndUpdate<IGuild>({ _id: defaultGuildID }, {
      $push: {
        members: user.id
      },
      $inc: {
        memberCount: 1
      }
    });

    return user;
  } catch (err) {
    console.error(err);
    return null;
  }
};
