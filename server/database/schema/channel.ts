import mongoose from "mongoose";
import { ChannelPermissions, IChannel } from "../../interfaces.js";

const ChannelsSchema = new mongoose.Schema<IChannel & mongoose.Document>({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  stickyMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "message",
    required: true,
  },
  messages: { type: Number, required: true },
  members: { type: [String], required: true },
  permissions: { type: Number, default: ChannelPermissions.PUBLIC }
});

export const Channel =
  mongoose.models.channel ||
  mongoose.model<IChannel>("channel", ChannelsSchema);
