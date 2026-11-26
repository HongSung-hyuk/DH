<template>
  <Page :help-tip="helpMsg">
    <IBox v-if="canManageAssetOtp" class="asset-otp-setting">
      <div class="asset-otp-row">
        <div>
          <strong>{{ $t('AssetConnectionOTP') }}</strong>
          <div class="asset-otp-help">{{ $t('AssetConnectionOTPHelp') }}</div>
        </div>
        <el-switch
          :model-value="assetOtpEnabled === true"
          :aria-label="$t('AssetConnectionOTP')"
          :loading="assetOtpLoading"
          :disabled="assetOtpEnabled === null || assetOtpLoading"
          @change="updateAssetOtp"
        />
      </div>
      <el-alert
        v-if="assetOtpEnabled === null && !assetOtpLoading"
        :title="$t('AssetConnectionOTPLoadFailed')"
        type="warning"
        :closable="false"
      />
    </IBox>
    <UserLoginACLTable />
  </Page>
</template>

<script>
import UserLoginACLTable from '@/views/acls/UserLoginACL/UserLoginACLTable.vue'
import Page from '@/layout/components/Page'
import IBox from '@/components/Common/IBox'

const assetOtpUrl = '/api/v1/settings/setting/?category=asset_connection_otp'
const assetOtpField = 'ASSET_CONNECTION_OTP_REQUIRED'

export default {
  components: {
    UserLoginACLTable,
    Page,
    IBox
  },
  data() {
    return {
      helpMsg: this.$t('UserLoginACLHelpMsg'),
      assetOtpEnabled: null,
      assetOtpLoading: false
    }
  },
  computed: {
    canManageAssetOtp() {
      return this.$hasPerm('settings.change_security')
    }
  },
  watch: {
    canManageAssetOtp: {
      immediate: true,
      handler(canManage) {
        if (canManage) this.loadAssetOtp()
      }
    }
  },
  methods: {
    async loadAssetOtp() {
      this.assetOtpLoading = true
      try {
        const settings = await this.$axios.get(assetOtpUrl)
        this.assetOtpEnabled = typeof settings[assetOtpField] === 'boolean' ? settings[assetOtpField] : null
      } catch {
        this.assetOtpEnabled = null
      } finally {
        this.assetOtpLoading = false
      }
    },
    async updateAssetOtp(enabled) {
      if (this.assetOtpLoading || this.assetOtpEnabled === null || !this.canManageAssetOtp) return
      this.assetOtpLoading = true
      try {
        const settings = await this.$axios.patch(assetOtpUrl, { [assetOtpField]: enabled })
        this.assetOtpEnabled = settings[assetOtpField]
        this.$message.success(this.$t('UpdateSuccessMsg'))
      } catch {
        await this.loadAssetOtp()
      } finally {
        this.assetOtpLoading = false
      }
    }
  }
}
</script>

<style scoped>
.asset-otp-setting {
  margin-bottom: 12px;
}

.asset-otp-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.asset-otp-help {
  margin-top: 4px;
  color: var(--el-text-color-secondary);
}
</style>
